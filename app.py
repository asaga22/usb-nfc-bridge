"""
NFC Bridge Service for ACR1222L USB Reader
Communicates with USB NFC reader and exposes WebSocket API
"""

from flask import Flask, request, jsonify
from flask_socketio import SocketIO, emit
from flask_cors import CORS
from smartcard.System import readers
from smartcard.util import toHexString
from smartcard.Exceptions import CardConnectionException, NoCardException
import threading
import time
import logging
from typing import Optional, Dict
import sys

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'nfc-bridge-secret-key-change-in-production'
CORS(app, resources={r"/*": {"origins": "*"}})
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Global state
scanning_active = False
scan_thread: Optional[threading.Thread] = None
last_card_uid: Optional[str] = None
reader_connection = None
connected_clients = set()


class NFCReaderManager:
    """Manages NFC reader connection and card detection"""
    
    def __init__(self):
        self.reader = None
        self.connection = None
        self.last_uid = None
        
    def find_reader(self) -> bool:
        """Find ACR1222L reader"""
        try:
            available_readers = readers()
            logger.info(f"Available readers: {available_readers}")
            
            if not available_readers:
                logger.error("No card readers found")
                return False
            
            # Try to find ACR1222L specifically
            for r in available_readers:
                reader_name = str(r).lower()
                if 'acr1222' in reader_name or 'acr122' in reader_name:
                    self.reader = r
                    logger.info(f"Found ACR1222L reader: {r}")
                    return True
            
            # Fallback to first available reader
            self.reader = available_readers[0]
            logger.warning(f"ACR1222L not found, using: {self.reader}")
            return True
            
        except Exception as e:
            logger.error(f"Error finding reader: {e}")
            return False
    
    def connect(self) -> bool:
        """Connect to the reader"""
        try:
            if not self.reader:
                if not self.find_reader():
                    return False
            
            self.connection = self.reader.createConnection()
            self.connection.connect()
            logger.info("Connected to reader")
            return True
            
        except Exception as e:
            logger.error(f"Error connecting to reader: {e}")
            return False
    
    def get_card_uid(self) -> Optional[str]:
        """Read card UID using PC/SC commands"""
        try:
            if not self.connection:
                if not self.connect():
                    return None
            
            # APDU command to get UID: FF CA 00 00 00
            GET_UID = [0xFF, 0xCA, 0x00, 0x00, 0x00]
            
            data, sw1, sw2 = self.connection.transmit(GET_UID)
            
            # Check if successful (90 00)
            if sw1 == 0x90 and sw2 == 0x00:
                uid = toHexString(data).replace(' ', ':')
                return uid.upper()
            else:
                logger.debug(f"Card not present or error: SW={sw1:02X} {sw2:02X}")
                return None
                
        except NoCardException:
            # No card present - this is normal, not an error
            return None
        except CardConnectionException as e:
            logger.warning(f"Card connection error: {e}")
            # Try to reconnect
            self.disconnect()
            return None
        except Exception as e:
            logger.error(f"Error reading card: {e}")
            return None
    
    def disconnect(self):
        """Disconnect from reader"""
        try:
            if self.connection:
                self.connection.disconnect()
                self.connection = None
                logger.info("Disconnected from reader")
        except Exception as e:
            logger.error(f"Error disconnecting: {e}")


# Global reader manager
nfc_manager = NFCReaderManager()


def scan_loop():
    """Background thread that continuously scans for NFC cards"""
    global scanning_active, last_card_uid
    
    logger.info("Scan loop started")
    
    # Connect to reader
    if not nfc_manager.connect():
        socketio.emit('error', {
            'message': 'Failed to connect to NFC reader. Please check connection.'
        })
        scanning_active = False
        return
    
    socketio.emit('status', {
        'scanning': True,
        'message': 'Scanning started'
    })
    
    consecutive_errors = 0
    max_errors = 10
    
    while scanning_active:
        try:
            uid = nfc_manager.get_card_uid()
            
            if uid:
                consecutive_errors = 0  # Reset error counter
                
                # Only emit if it's a new card
                if uid != last_card_uid:
                    last_card_uid = uid
                    logger.info(f"Card detected: {uid}")
                    
                    socketio.emit('card_detected', {
                        'serialNumber': uid,
                        'timestamp': time.time(),
                        'method': 'USB Bridge Service (ACR1222L)'
                    })
                    
                    # Wait a bit to avoid rapid re-reads
                    time.sleep(1)
            else:
                # Card removed or not present
                if last_card_uid is not None:
                    logger.info("Card removed")
                    last_card_uid = None
                    socketio.emit('card_removed', {
                        'timestamp': time.time()
                    })
                
                # Short sleep when no card present
                time.sleep(0.3)
                
        except Exception as e:
            consecutive_errors += 1
            logger.error(f"Error in scan loop: {e} (consecutive errors: {consecutive_errors})")
            
            if consecutive_errors >= max_errors:
                logger.error("Too many consecutive errors, stopping scan")
                socketio.emit('error', {
                    'message': f'Scanner error: {str(e)}. Scanning stopped.'
                })
                scanning_active = False
                break
            
            time.sleep(0.5)
    
    # Cleanup
    nfc_manager.disconnect()
    logger.info("Scan loop stopped")
    
    socketio.emit('status', {
        'scanning': False,
        'message': 'Scanning stopped'
    })


# WebSocket event handlers
@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    client_id = request.sid
    connected_clients.add(client_id)
    logger.info(f"Client connected: {client_id} (Total: {len(connected_clients)})")
    
    emit('connected', {
        'message': 'Connected to NFC Bridge Service',
        'scanning': scanning_active
    })


@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    client_id = request.sid
    connected_clients.discard(client_id)
    logger.info(f"Client disconnected: {client_id} (Total: {len(connected_clients)})")


@socketio.on('start_scan')
def handle_start_scan(data=None):
    """Start NFC scanning"""
    global scanning_active, scan_thread
    
    if scanning_active:
        emit('error', {'message': 'Scanning already active'})
        return
    
    logger.info("Starting scan requested")
    scanning_active = True
    scan_thread = threading.Thread(target=scan_loop, daemon=True)
    scan_thread.start()


@socketio.on('stop_scan')
def handle_stop_scan(data=None):
    """Stop NFC scanning"""
    global scanning_active, last_card_uid
    
    logger.info("Stopping scan requested")
    scanning_active = False
    last_card_uid = None
    
    emit('status', {
        'scanning': False,
        'message': 'Scanning stopped'
    })


@socketio.on('check_reader')
def handle_check_reader(data=None):
    """Check if reader is available"""
    try:
        available = nfc_manager.find_reader()
        
        emit('reader_status', {
            'available': available,
            'reader': str(nfc_manager.reader) if nfc_manager.reader else None,
            'message': 'Reader found' if available else 'No reader found'
        })
    except Exception as e:
        emit('error', {
            'message': f'Error checking reader: {str(e)}'
        })


# REST API endpoints
@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'ok',
        'service': 'NFC Bridge Service',
        'scanning': scanning_active,
        'connected_clients': len(connected_clients)
    })


@app.route('/reader/status', methods=['GET'])
def reader_status():
    """Get reader status"""
    try:
        available = nfc_manager.find_reader()
        return jsonify({
            'available': available,
            'reader': str(nfc_manager.reader) if nfc_manager.reader else None,
            'scanning': scanning_active
        })
    except Exception as e:
        return jsonify({
            'error': str(e)
        }), 500


@app.route('/scan/start', methods=['POST'])
def start_scan_rest():
    """Start scanning via REST API"""
    global scanning_active, scan_thread
    
    if scanning_active:
        return jsonify({'message': 'Already scanning'}), 400
    
    scanning_active = True
    scan_thread = threading.Thread(target=scan_loop, daemon=True)
    scan_thread.start()
    
    return jsonify({'message': 'Scanning started'})


@app.route('/scan/stop', methods=['POST'])
def stop_scan_rest():
    """Stop scanning via REST API"""
    global scanning_active
    
    scanning_active = False
    return jsonify({'message': 'Scanning stopped'})


if __name__ == '__main__':
    logger.info("Starting NFC Bridge Service")
    logger.info("WebSocket server will be available at http://localhost:5000")
    
    # Check if reader is available at startup
    if nfc_manager.find_reader():
        logger.info(f"Reader found: {nfc_manager.reader}")
    else:
        logger.warning("No reader found at startup")
    
    # Run the server
    socketio.run(app, host='0.0.0.0', port=5000, debug=False, allow_unsafe_werkzeug=True)