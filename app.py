"""
NFC Bridge Service for ACR1222L USB Reader
Communicates with USB NFC reader and exposes WebSocket API
Supports both reading and writing to NFC cards
"""

from flask import Flask, request, jsonify
from flask_socketio import SocketIO, emit
from flask_cors import CORS
from smartcard.System import readers
from smartcard.util import toHexString, toBytes
from smartcard.Exceptions import CardConnectionException, NoCardException
import threading
import time
import logging
import json
from typing import Optional, Dict, Any
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
last_card_data: Optional[Dict] = None
reader_connection = None
connected_clients = set()
write_lock = threading.Lock()
pending_write: Optional[Dict] = None


class NFCReaderManager:
    """Manages NFC reader connection and card detection"""
    
    # NTAG213/215/216 memory layout
    NTAG_USER_DATA_START = 4  # Page 4 is first user data page
    NTAG_PAGE_SIZE = 4  # 4 bytes per page
    
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
            
            for r in available_readers:
                reader_name = str(r).lower()
                if 'acr1222' in reader_name or 'acr122' in reader_name:
                    self.reader = r
                    logger.info(f"Found ACR1222L reader: {r}")
                    return True
            
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
    
    def ensure_connection(self) -> bool:
        """Ensure we have a valid connection"""
        if self.connection:
            try:
                # Test connection with a simple command
                self.connection.transmit([0xFF, 0x00, 0x00, 0x00, 0x00])
                return True
            except:
                self.disconnect()
        return self.connect()
    
    def get_card_uid(self) -> Optional[str]:
        """Read card UID using PC/SC commands"""
        try:
            if not self.connection:
                if not self.connect():
                    return None
            
            GET_UID = [0xFF, 0xCA, 0x00, 0x00, 0x00]
            data, sw1, sw2 = self.connection.transmit(GET_UID)
            
            if sw1 == 0x90 and sw2 == 0x00:
                uid = toHexString(data).replace(' ', ':')
                return uid.upper()
            else:
                logger.debug(f"Card not present or error: SW={sw1:02X} {sw2:02X}")
                return None
                
        except NoCardException:
            return None
        except CardConnectionException as e:
            logger.warning(f"Card connection error: {e}")
            self.disconnect()
            return None
        except Exception as e:
            logger.error(f"Error reading card: {e}")
            return None
    
    def read_page(self, page: int) -> Optional[bytes]:
        """Read a single page (4 bytes) from NFC tag"""
        try:
            if not self.ensure_connection():
                return None
            
            # APDU: FF B0 00 [page] 04 (Read Binary)
            READ_CMD = [0xFF, 0xB0, 0x00, page, 0x04]
            data, sw1, sw2 = self.connection.transmit(READ_CMD)
            
            if sw1 == 0x90 and sw2 == 0x00:
                return bytes(data)
            else:
                logger.debug(f"Read page {page} failed: SW={sw1:02X} {sw2:02X}")
                return None
                
        except Exception as e:
            logger.error(f"Error reading page {page}: {e}")
            return None
    
    def write_page(self, page: int, data: bytes) -> bool:
        """Write 4 bytes to a single page"""
        try:
            if not self.ensure_connection():
                return False
            
            if len(data) != 4:
                logger.error(f"Data must be exactly 4 bytes, got {len(data)}")
                return False
            
            # APDU: FF D6 00 [page] 04 [4 bytes data] (Update Binary)
            WRITE_CMD = [0xFF, 0xD6, 0x00, page, 0x04] + list(data)
            _, sw1, sw2 = self.connection.transmit(WRITE_CMD)
            
            if sw1 == 0x90 and sw2 == 0x00:
                logger.info(f"Successfully wrote to page {page}")
                return True
            else:
                logger.error(f"Write to page {page} failed: SW={sw1:02X} {sw2:02X}")
                return False
                
        except Exception as e:
            logger.error(f"Error writing page {page}: {e}")
            return False
    
    def read_user_data(self, start_page: int = 4, num_pages: int = 36) -> Optional[bytes]:
        """Read user data area from NFC tag"""
        try:
            all_data = bytearray()
            
            for page in range(start_page, start_page + num_pages):
                page_data = self.read_page(page)
                if page_data is None:
                    break
                all_data.extend(page_data)
            
            return bytes(all_data) if all_data else None
            
        except Exception as e:
            logger.error(f"Error reading user data: {e}")
            return None
    
    def parse_ndef_text(self, data: bytes) -> Optional[str]:
        """Parse NDEF text record from raw data"""
        try:
            if len(data) < 10:
                return None
            
            # Look for NDEF message start (0x03 = NDEF message TLV)
            idx = 0
            while idx < len(data) - 2:
                if data[idx] == 0x03:  # NDEF Message TLV
                    length = data[idx + 1]
                    if length == 0 or idx + 2 + length > len(data):
                        idx += 1
                        continue
                    
                    ndef_data = data[idx + 2:idx + 2 + length]
                    
                    # Parse NDEF record
                    if len(ndef_data) > 7:
                        # Skip NDEF header to get to payload
                        tnf = ndef_data[0] & 0x07
                        type_length = ndef_data[1]
                        payload_length = ndef_data[2]
                        
                        if tnf == 0x01 and type_length == 1:  # Well-known type
                            record_type = ndef_data[3]
                            if record_type == 0x54:  # 'T' for Text
                                # Text record: status byte + language code + text
                                payload_start = 4
                                if payload_start < len(ndef_data):
                                    status = ndef_data[payload_start]
                                    lang_len = status & 0x3F
                                    text_start = payload_start + 1 + lang_len
                                    if text_start < len(ndef_data):
                                        text_data = ndef_data[text_start:payload_start + payload_length]
                                        # Remove null bytes
                                        text = bytes(b for b in text_data if b != 0).decode('utf-8', errors='ignore')
                                        return text
                    break
                idx += 1
            
            return None
            
        except Exception as e:
            logger.error(f"Error parsing NDEF: {e}")
            return None
    
    def create_ndef_text_record(self, text: str) -> bytes:
        """Create NDEF text record"""
        text_bytes = text.encode('utf-8')
        lang_code = b'en'
        
        # Text record payload: status byte + language code + text
        status_byte = len(lang_code)  # UTF-8 encoding (bit 7 = 0)
        payload = bytes([status_byte]) + lang_code + text_bytes
        
        # NDEF record header
        # MB=1, ME=1, CF=0, SR=1, IL=0, TNF=001 (Well-known)
        header = 0xD1
        type_length = 1
        payload_length = len(payload)
        record_type = ord('T')
        
        ndef_record = bytes([header, type_length, payload_length, record_type]) + payload
        
        # TLV wrapper
        # 0x03 = NDEF Message TLV, length, data, 0xFE = Terminator
        tlv = bytes([0x03, len(ndef_record)]) + ndef_record + bytes([0xFE])
        
        return tlv
    
    def write_ndef_text(self, text: str, start_page: int = 4) -> bool:
        """Write NDEF text record to NFC tag"""
        try:
            ndef_data = self.create_ndef_text_record(text)
            
            # Pad to page boundary
            padding_needed = (4 - (len(ndef_data) % 4)) % 4
            ndef_data = ndef_data + bytes([0x00] * padding_needed)
            
            logger.info(f"Writing {len(ndef_data)} bytes ({len(ndef_data)//4} pages)")
            
            # Write page by page
            for i in range(0, len(ndef_data), 4):
                page = start_page + (i // 4)
                page_data = ndef_data[i:i+4]
                
                if not self.write_page(page, page_data):
                    logger.error(f"Failed to write page {page}")
                    return False
                
                time.sleep(0.05)  # Small delay between writes
            
            logger.info(f"Successfully wrote NDEF text record")
            return True
            
        except Exception as e:
            logger.error(f"Error writing NDEF text: {e}")
            return False
    
    def write_json_data(self, data: Dict) -> bool:
        """Write JSON data as NDEF text record"""
        try:
            json_str = json.dumps(data, separators=(',', ':'))
            logger.info(f"Writing JSON data: {json_str[:100]}...")
            return self.write_ndef_text(json_str)
        except Exception as e:
            logger.error(f"Error writing JSON data: {e}")
            return False
    
    def read_json_data(self) -> Optional[Dict]:
        """Read and parse JSON data from NFC tag"""
        try:
            raw_data = self.read_user_data()
            if not raw_data:
                return None
            
            text = self.parse_ndef_text(raw_data)
            if not text:
                return None
            
            # Try to parse as JSON
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                logger.debug(f"Data is not JSON: {text[:50]}...")
                return {'raw': text}
                
        except Exception as e:
            logger.error(f"Error reading JSON data: {e}")
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
    global scanning_active, last_card_uid, last_card_data, pending_write
    
    logger.info("Scan loop started")
    
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
                consecutive_errors = 0
                
                # Check for pending write operation
                with write_lock:
                    if pending_write and pending_write.get('targetUid') == uid:
                        write_data = pending_write
                        pending_write = None
                        
                        logger.info(f"Processing pending write for {uid}")
                        socketio.emit('write_started', {
                            'serialNumber': uid,
                            'timestamp': time.time()
                        })
                        
                        success = nfc_manager.write_json_data(write_data.get('data', {}))
                        
                        if success:
                            # Verify write
                            time.sleep(0.1)
                            verify_data = nfc_manager.read_json_data()
                            
                            socketio.emit('write_complete', {
                                'success': True,
                                'serialNumber': uid,
                                'data': write_data.get('data'),
                                'verified': verify_data is not None,
                                'timestamp': time.time()
                            })
                        else:
                            socketio.emit('write_complete', {
                                'success': False,
                                'serialNumber': uid,
                                'error': 'Write operation failed',
                                'timestamp': time.time()
                            })
                        
                        time.sleep(1)
                        continue
                
                # Normal card detection
                if uid != last_card_uid:
                    last_card_uid = uid
                    logger.info(f"Card detected: {uid}")
                    
                    # Read existing data
                    card_data = nfc_manager.read_json_data()
                    last_card_data = card_data
                    
                    socketio.emit('card_detected', {
                        'serialNumber': uid,
                        'userData': card_data,
                        'timestamp': time.time(),
                        'method': 'USB Bridge Service (ACR1222L)'
                    })
                    
                    time.sleep(0.5)
            else:
                if last_card_uid is not None:
                    logger.info("Card removed")
                    last_card_uid = None
                    last_card_data = None
                    socketio.emit('card_removed', {
                        'timestamp': time.time()
                    })
                
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
        'scanning': scanning_active,
        'capabilities': ['read', 'write']
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
    global scanning_active, last_card_uid, last_card_data, pending_write
    
    logger.info("Stopping scan requested")
    scanning_active = False
    last_card_uid = None
    last_card_data = None
    
    with write_lock:
        pending_write = None
    
    emit('status', {
        'scanning': False,
        'message': 'Scanning stopped'
    })


@socketio.on('write_card')
def handle_write_card(data: Dict):
    """Queue a write operation for the current or specified card"""
    global pending_write, last_card_uid
    
    target_uid = data.get('serialNumber') or data.get('targetUid') or last_card_uid
    write_data = data.get('data', {})
    
    if not target_uid:
        emit('write_complete', {
            'success': False,
            'error': 'No card detected. Please place a card on the reader.'
        })
        return
    
    if not write_data:
        emit('write_complete', {
            'success': False,
            'error': 'No data provided to write'
        })
        return
    
    logger.info(f"Write requested for card {target_uid}: {write_data}")
    
    # If card is currently on reader and matches, write immediately
    if last_card_uid == target_uid:
        emit('write_started', {
            'serialNumber': target_uid,
            'timestamp': time.time()
        })
        
        success = nfc_manager.write_json_data(write_data)
        
        if success:
            time.sleep(0.1)
            verify_data = nfc_manager.read_json_data()
            
            emit('write_complete', {
                'success': True,
                'serialNumber': target_uid,
                'data': write_data,
                'verified': verify_data is not None,
                'timestamp': time.time()
            })
        else:
            emit('write_complete', {
                'success': False,
                'serialNumber': target_uid,
                'error': 'Write operation failed',
                'timestamp': time.time()
            })
    else:
        # Queue for when card is detected
        with write_lock:
            pending_write = {
                'targetUid': target_uid,
                'data': write_data,
                'timestamp': time.time()
            }
        
        emit('write_queued', {
            'serialNumber': target_uid,
            'message': 'Write queued. Please place the card on the reader.',
            'timestamp': time.time()
        })


@socketio.on('read_card')
def handle_read_card(data=None):
    """Read data from current card"""
    global last_card_uid
    
    if not last_card_uid:
        emit('read_complete', {
            'success': False,
            'error': 'No card detected. Please place a card on the reader.'
        })
        return
    
    card_data = nfc_manager.read_json_data()
    
    emit('read_complete', {
        'success': True,
        'serialNumber': last_card_uid,
        'data': card_data,
        'timestamp': time.time()
    })


@socketio.on('check_reader')
def handle_check_reader(data=None):
    """Check if reader is available"""
    try:
        available = nfc_manager.find_reader()
        
        emit('reader_status', {
            'available': available,
            'reader': str(nfc_manager.reader) if nfc_manager.reader else None,
            'message': 'Reader found' if available else 'No reader found',
            'capabilities': ['read', 'write'] if available else []
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
        'connected_clients': len(connected_clients),
        'capabilities': ['read', 'write']
    })


@app.route('/reader/status', methods=['GET'])
def reader_status():
    """Get reader status"""
    try:
        available = nfc_manager.find_reader()
        return jsonify({
            'available': available,
            'reader': str(nfc_manager.reader) if nfc_manager.reader else None,
            'scanning': scanning_active,
            'currentCard': last_card_uid,
            'capabilities': ['read', 'write']
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


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


@app.route('/card/write', methods=['POST'])
def write_card_rest():
    """Write to card via REST API"""
    global pending_write, last_card_uid
    
    data = request.json
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    target_uid = data.get('serialNumber') or last_card_uid
    write_data = data.get('data', {})
    
    if not target_uid:
        return jsonify({'error': 'No card detected'}), 400
    
    if not write_data:
        return jsonify({'error': 'No data to write'}), 400
    
    if last_card_uid == target_uid:
        success = nfc_manager.write_json_data(write_data)
        if success:
            return jsonify({
                'success': True,
                'serialNumber': target_uid,
                'message': 'Data written successfully'
            })
        else:
            return jsonify({'error': 'Write failed'}), 500
    else:
        with write_lock:
            pending_write = {
                'targetUid': target_uid,
                'data': write_data,
                'timestamp': time.time()
            }
        return jsonify({
            'queued': True,
            'serialNumber': target_uid,
            'message': 'Write queued - place card on reader'
        }), 202


@app.route('/card/read', methods=['GET'])
def read_card_rest():
    """Read current card via REST API"""
    if not last_card_uid:
        return jsonify({'error': 'No card detected'}), 400
    
    card_data = nfc_manager.read_json_data()
    return jsonify({
        'serialNumber': last_card_uid,
        'data': card_data
    })


if __name__ == '__main__':
    logger.info("Starting NFC Bridge Service")
    logger.info("WebSocket server will be available at http://localhost:5000")
    logger.info("Capabilities: READ, WRITE")
    
    if nfc_manager.find_reader():
        logger.info(f"Reader found: {nfc_manager.reader}")
    else:
        logger.warning("No reader found at startup")
    
    socketio.run(app, host='0.0.0.0', port=5000, debug=False, allow_unsafe_werkzeug=True)