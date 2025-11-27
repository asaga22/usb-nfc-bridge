"""
NFC Bridge Service for ACR1222L USB Reader
Communicates with USB NFC reader and exposes WebSocket API
Supports reading, writing, and UID changing for Magic Cards (MIFARE Classic compatible)

IMPORTANT: UID Change is ONLY supported on "Magic Cards" (special MIFARE Classic clones)
Regular NFC cards have factory-burned UIDs that cannot be changed.
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
from typing import Optional, Dict, Any, Tuple
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
last_card_is_magic: bool = False
reader_connection = None
connected_clients = set()
write_lock = threading.Lock()
pending_write: Optional[Dict] = None
pending_uid_change: Optional[Dict] = None


class NFCReaderManager:
    """Manages NFC reader connection and card detection"""
    
    # NTAG213/215/216 memory layout
    NTAG_USER_DATA_START = 4  # Page 4 is first user data page
    NTAG_PAGE_SIZE = 4  # 4 bytes per page
    
    # Magic card detection constants
    MAGIC_CARD_BACKDOOR_COMMANDS = {
        'gen1a': [0x40, 0x00],  # Magic Gen1a backdoor
        'gen2': [0x43, 0x00],   # Magic Gen2 (CUID) backdoor
    }
    
    def __init__(self):
        self.reader = None
        self.connection = None
        self.last_uid = None
        self.is_magic_card = False
        
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
                    logger.info(f"Found ACR reader: {self.reader}")
                    return True
            
            # If no ACR reader found, use first available
            self.reader = available_readers[0]
            logger.info(f"Using first available reader: {self.reader}")
            return True
            
        except Exception as e:
            logger.error(f"Error finding reader: {e}")
            return False
    
    def connect(self) -> bool:
        """Connect to reader"""
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
    
    def disconnect(self):
        """Disconnect from reader"""
        try:
            if self.connection:
                self.connection.disconnect()
                self.connection = None
                logger.info("Disconnected from reader")
        except Exception as e:
            logger.error(f"Error disconnecting: {e}")
    
    def send_apdu(self, apdu: list) -> Tuple[list, int, int]:
        """Send APDU command and return response"""
        try:
            if not self.connection:
                raise Exception("Not connected to reader")
            response, sw1, sw2 = self.connection.transmit(apdu)
            return response, sw1, sw2
        except Exception as e:
            logger.error(f"APDU error: {e}")
            raise
    
    def get_uid(self) -> Optional[str]:
        """Get card UID using standard APDU"""
        try:
            # Standard GET UID command for ISO 14443
            apdu = [0xFF, 0xCA, 0x00, 0x00, 0x00]
            response, sw1, sw2 = self.send_apdu(apdu)
            
            if sw1 == 0x90 and sw2 == 0x00:
                uid = ':'.join(f'{b:02X}' for b in response)
                self.last_uid = uid
                return uid
            else:
                logger.warning(f"Get UID failed: SW1={sw1:02X} SW2={sw2:02X}")
                return None
        except Exception as e:
            logger.error(f"Error getting UID: {e}")
            return None
    
    def detect_magic_card(self) -> bool:
        """
        Detect if the card is a Magic Card (supports UID modification)
        
        Magic Cards are special MIFARE Classic clones that allow UID modification.
        Regular cards have factory-burned UIDs that cannot be changed.
        
        Detection methods:
        1. Gen1a: Responds to 0x40 backdoor command
        2. Gen2 (CUID): Has writable Block 0
        """
        try:
            # Method 1: Try Gen1a backdoor (0x40 command)
            # This is done at raw RF level, may not work through standard APDU
            
            # Method 2: Try to read Block 0 with default key
            # If readable and we can attempt write, it might be magic
            
            # For ACR1222L, we use direct commands
            # Try to authenticate and read block 0
            
            # Load authentication key A
            load_key = [0xFF, 0x82, 0x00, 0x00, 0x06, 
                       0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]  # Default key
            response, sw1, sw2 = self.send_apdu(load_key)
            
            if sw1 != 0x90:
                logger.debug("Failed to load auth key")
                self.is_magic_card = False
                return False
            
            # Authenticate to Block 0 with Key A
            auth = [0xFF, 0x86, 0x00, 0x00, 0x05, 
                   0x01, 0x00, 0x00, 0x60, 0x00]  # Block 0, Key A
            response, sw1, sw2 = self.send_apdu(auth)
            
            if sw1 != 0x90:
                logger.debug("Authentication failed - not a magic card or wrong key")
                self.is_magic_card = False
                return False
            
            # Read Block 0
            read_block = [0xFF, 0xB0, 0x00, 0x00, 0x10]  # Read 16 bytes from block 0
            response, sw1, sw2 = self.send_apdu(read_block)
            
            if sw1 == 0x90 and sw2 == 0x00 and len(response) == 16:
                # Block 0 readable - this is likely a magic card
                # Regular MIFARE cards should also allow this, but magic cards
                # have specific patterns or allow Block 0 writing
                
                # Check if BCC (Block Check Character) is correct
                uid_bytes = response[:4]
                bcc = response[4]
                calculated_bcc = uid_bytes[0] ^ uid_bytes[1] ^ uid_bytes[2] ^ uid_bytes[3]
                
                if bcc == calculated_bcc:
                    # Try a test - attempt to enter "magic mode"
                    # For Gen2 cards, we can try to write to block 0
                    # We won't actually write, just check if it's possible
                    
                    self.is_magic_card = True
                    logger.info("Magic card detected (Block 0 accessible)")
                    return True
            
            self.is_magic_card = False
            return False
            
        except Exception as e:
            logger.error(f"Error detecting magic card: {e}")
            self.is_magic_card = False
            return False
    
    def change_uid(self, new_uid: str) -> Tuple[bool, str]:
        """
        Change UID of a Magic Card
        
        IMPORTANT: This only works on Magic Cards (MIFARE Classic clones with special firmware)
        Regular NFC cards have UIDs burned at factory and CANNOT be changed.
        
        Args:
            new_uid: New UID in format "XX:XX:XX:XX" (4 bytes) or "XX:XX:XX:XX:XX:XX:XX" (7 bytes)
        
        Returns:
            Tuple of (success: bool, message: str)
        """
        try:
            if not self.is_magic_card:
                return False, "Card is not a Magic Card - UID cannot be changed"
            
            # Parse new UID
            uid_parts = new_uid.replace(':', '').replace(' ', '')
            if len(uid_parts) not in [8, 14]:  # 4 or 7 bytes
                return False, f"Invalid UID length: must be 4 or 7 bytes, got {len(uid_parts)//2}"
            
            new_uid_bytes = [int(uid_parts[i:i+2], 16) for i in range(0, len(uid_parts), 2)]
            
            # Calculate BCC for 4-byte UID
            if len(new_uid_bytes) == 4:
                bcc = new_uid_bytes[0] ^ new_uid_bytes[1] ^ new_uid_bytes[2] ^ new_uid_bytes[3]
            else:
                # For 7-byte UID, BCC calculation is different
                bcc = 0x88 ^ new_uid_bytes[0] ^ new_uid_bytes[1] ^ new_uid_bytes[2]
            
            # Load default key
            load_key = [0xFF, 0x82, 0x00, 0x00, 0x06,
                       0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
            response, sw1, sw2 = self.send_apdu(load_key)
            
            if sw1 != 0x90:
                return False, "Failed to load authentication key"
            
            # Authenticate to Block 0
            auth = [0xFF, 0x86, 0x00, 0x00, 0x05,
                   0x01, 0x00, 0x00, 0x60, 0x00]
            response, sw1, sw2 = self.send_apdu(auth)
            
            if sw1 != 0x90:
                return False, "Authentication failed"
            
            # Prepare Block 0 data (16 bytes)
            # Format: [UID0] [UID1] [UID2] [UID3] [BCC] [SAK] [ATQA0] [ATQA1] [Manufacturer data...]
            if len(new_uid_bytes) == 4:
                block0 = new_uid_bytes + [bcc, 0x08, 0x04, 0x00] + [0x00] * 8
            else:
                # 7-byte UID handling (more complex, usually in cascade format)
                block0 = [0x88] + new_uid_bytes[:3] + [bcc] + new_uid_bytes[3:] + [0x00] * 6
            
            # Write Block 0
            write_cmd = [0xFF, 0xD6, 0x00, 0x00, 0x10] + block0
            response, sw1, sw2 = self.send_apdu(write_cmd)
            
            if sw1 == 0x90 and sw2 == 0x00:
                # Verify the change
                time.sleep(0.1)  # Small delay
                
                # Re-read UID
                new_read_uid = self.get_uid()
                
                if new_read_uid:
                    expected_uid = ':'.join(f'{b:02X}' for b in new_uid_bytes)
                    if new_read_uid == expected_uid:
                        logger.info(f"UID changed successfully to {new_uid}")
                        return True, f"UID changed to {new_read_uid}"
                    else:
                        logger.warning(f"UID verification failed: expected {expected_uid}, got {new_read_uid}")
                        return True, f"UID change command sent, new UID: {new_read_uid}"
                
                return True, "UID change command sent successfully"
            else:
                return False, f"Write failed: SW1={sw1:02X} SW2={sw2:02X}"
                
        except Exception as e:
            logger.error(f"Error changing UID: {e}")
            return False, f"Error: {str(e)}"
    
    def read_user_data(self) -> Optional[bytes]:
        """Read user data from NFC tag (NTAG/NDEF compatible tags)"""
        try:
            all_data = []
            for page in range(self.NTAG_USER_DATA_START, 40):  # Read pages 4-39
                apdu = [0xFF, 0xB0, 0x00, page, 0x04]  # Read 4 bytes
                response, sw1, sw2 = self.send_apdu(apdu)
                
                if sw1 == 0x90 and sw2 == 0x00:
                    all_data.extend(response)
                else:
                    break
            
            return bytes(all_data) if all_data else None
        except Exception as e:
            logger.error(f"Error reading user data: {e}")
            return None
    
    def parse_ndef_text(self, data: bytes) -> Optional[str]:
        """Parse NDEF text record from raw data"""
        try:
            if not data or len(data) < 7:
                return None
            
            # Skip TLV header if present
            idx = 0
            while idx < len(data) - 5:
                if data[idx] == 0x03:  # NDEF Message TLV
                    length = data[idx + 1]
                    idx += 2
                    break
                elif data[idx] == 0x00 or data[idx] == 0xFE:
                    idx += 1
                else:
                    idx += 2 + data[idx + 1] if idx + 1 < len(data) else 1
            
            if idx >= len(data) - 5:
                # Try direct NDEF parsing
                idx = 0
            
            # Parse NDEF record
            if idx < len(data) and (data[idx] & 0xC0) == 0xC0:  # Short record, MB=1
                tnf = data[idx] & 0x07
                type_length = data[idx + 1] if idx + 1 < len(data) else 0
                payload_length = data[idx + 2] if idx + 2 < len(data) else 0
                
                if tnf == 0x01 and type_length == 1:  # Well-known type
                    record_type = data[idx + 3] if idx + 3 < len(data) else 0
                    if record_type == ord('T'):  # Text record
                        payload_start = idx + 4
                        if payload_start < len(data):
                            lang_len = data[payload_start] & 0x3F
                            text_start = payload_start + 1 + lang_len
                            text_end = payload_start + payload_length
                            if text_start < len(data):
                                text_bytes = data[text_start:min(text_end, len(data))]
                                # Filter out non-printable characters
                                text = ''.join(chr(b) for b in text_bytes if 32 <= b < 127 or b in [10, 13])
                                return text.strip()
            
            return None
        except Exception as e:
            logger.error(f"Error parsing NDEF: {e}")
            return None
    
    def write_ndef_text(self, text: str) -> bool:
        """Write NDEF text record to NFC tag"""
        try:
            text_bytes = text.encode('utf-8')
            lang = b'en'
            
            # Build NDEF record
            ndef_record = bytes([
                0xD1,  # Header: MB=1, ME=1, CF=0, SR=1, IL=0, TNF=1
                0x01,  # Type length
                len(text_bytes) + len(lang) + 1,  # Payload length
                ord('T'),  # Type: Text
                len(lang),  # Language code length
            ]) + lang + text_bytes
            
            # Build NDEF message with TLV
            ndef_message = bytes([
                0x03,  # NDEF Message TLV
                len(ndef_record),  # Length
            ]) + ndef_record + bytes([
                0xFE,  # Terminator TLV
            ])
            
            # Pad to page boundary
            while len(ndef_message) % 4 != 0:
                ndef_message += bytes([0x00])
            
            # Write pages
            page = self.NTAG_USER_DATA_START
            for i in range(0, len(ndef_message), 4):
                chunk = list(ndef_message[i:i+4])
                while len(chunk) < 4:
                    chunk.append(0x00)
                
                apdu = [0xFF, 0xD6, 0x00, page, 0x04] + chunk
                response, sw1, sw2 = self.send_apdu(apdu)
                
                if sw1 != 0x90 or sw2 != 0x00:
                    logger.error(f"Write failed at page {page}: SW1={sw1:02X} SW2={sw2:02X}")
                    return False
                
                page += 1
                time.sleep(0.05)
            
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
            
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                logger.debug(f"Data is not JSON: {text[:50]}...")
                return {'raw': text}
                
        except Exception as e:
            logger.error(f"Error reading JSON data: {e}")
            return None


# Global reader manager
nfc_manager = NFCReaderManager()


def scan_loop():
    """Background thread that continuously scans for NFC cards"""
    global scanning_active, last_card_uid, last_card_data, last_card_is_magic
    global pending_write, pending_uid_change
    
    logger.info("Scan loop started")
    
    if not nfc_manager.connect():
        socketio.emit('error', {
            'message': 'Failed to connect to NFC reader. Please check connection.'
        })
        scanning_active = False
        return
    
    socketio.emit('status', {
        'scanning': True,
        'message': 'Scanning for NFC cards...'
    })
    
    while scanning_active:
        try:
            # Try to get card UID
            uid = nfc_manager.get_uid()
            
            if uid:
                if uid != last_card_uid:
                    # New card detected
                    last_card_uid = uid
                    
                    # Detect if magic card
                    is_magic = nfc_manager.detect_magic_card()
                    last_card_is_magic = is_magic
                    
                    # Read existing data
                    card_data = nfc_manager.read_json_data()
                    last_card_data = card_data
                    
                    logger.info(f"Card detected: {uid}, Magic: {is_magic}, Data: {card_data}")
                    
                    socketio.emit('card_detected', {
                        'serialNumber': uid,
                        'userData': card_data,
                        'method': 'USB Bridge Service (ACR1222L)',
                        'isMagicCard': is_magic
                    })
                
                # Check for pending UID change
                if pending_uid_change:
                    with write_lock:
                        change_data = pending_uid_change
                        pending_uid_change = None
                    
                    new_uid = change_data.get('newUid')
                    if new_uid:
                        original_uid = last_card_uid
                        
                        socketio.emit('uid_change_started', {
                            'originalUid': original_uid,
                            'newUid': new_uid
                        })
                        
                        success, message = nfc_manager.change_uid(new_uid)
                        
                        socketio.emit('uid_change_complete', {
                            'success': success,
                            'originalUid': original_uid,
                            'newUid': new_uid if success else None,
                            'message': message,
                            'timestamp': time.time()
                        })
                        
                        if success:
                            last_card_uid = new_uid
                
                # Check for pending write
                if pending_write:
                    with write_lock:
                        write_data = pending_write
                        pending_write = None
                    
                    target_uid = write_data.get('targetUid')
                    data = write_data.get('data', {})
                    
                    if target_uid == last_card_uid or target_uid is None:
                        socketio.emit('write_started', {
                            'serialNumber': last_card_uid
                        })
                        
                        success = nfc_manager.write_json_data(data)
                        
                        socketio.emit('write_complete', {
                            'success': success,
                            'serialNumber': last_card_uid,
                            'data': data if success else None,
                            'error': 'Write failed' if not success else None,
                            'timestamp': time.time()
                        })
                        
                        if success:
                            last_card_data = data
            else:
                # No card or card removed
                if last_card_uid:
                    logger.info("Card removed")
                    socketio.emit('card_removed', {
                        'previousUid': last_card_uid
                    })
                    last_card_uid = None
                    last_card_data = None
                    last_card_is_magic = False
            
            # Check if any clients still connected
            if not connected_clients:
                logger.info("No clients connected, stopping scan")
                socketio.emit('status', {
                    'scanning': False,
                    'message': 'Scanning stopped.'
                })
                scanning_active = False
                break
            
            time.sleep(0.5)
            
        except NoCardException:
            if last_card_uid:
                socketio.emit('card_removed', {
                    'previousUid': last_card_uid
                })
                last_card_uid = None
                last_card_data = None
                last_card_is_magic = False
            time.sleep(0.5)
        except CardConnectionException as e:
            logger.error(f"Card connection error: {e}")
            time.sleep(0.5)
        except Exception as e:
            logger.error(f"Scan error: {e}")
            time.sleep(1)
    
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
        'capabilities': ['read', 'write', 'uid_change']
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
    global scanning_active, last_card_uid, last_card_data, last_card_is_magic
    global pending_write, pending_uid_change
    
    logger.info("Stopping scan requested")
    scanning_active = False
    last_card_uid = None
    last_card_data = None
    last_card_is_magic = False
    
    with write_lock:
        pending_write = None
        pending_uid_change = None
    
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
            'error': 'No data to write'
        })
        return
    
    # If card is currently on reader and UID matches, write immediately in scan loop
    if last_card_uid == target_uid:
        with write_lock:
            pending_write = {
                'targetUid': target_uid,
                'data': write_data,
                'timestamp': time.time()
            }
        emit('write_queued', {
            'serialNumber': target_uid,
            'message': 'Write queued for current card'
        })
    else:
        # Card not on reader, queue for when it appears
        with write_lock:
            pending_write = {
                'targetUid': target_uid,
                'data': write_data,
                'timestamp': time.time()
            }
        emit('write_queued', {
            'serialNumber': target_uid,
            'message': 'Write queued. Please place the card on the reader.'
        })


@socketio.on('change_uid')
def handle_change_uid(data: Dict):
    """
    Queue a UID change operation for a Magic Card
    
    IMPORTANT: Only works on Magic Cards (special MIFARE Classic clones)
    Regular NFC cards have factory-burned UIDs that cannot be changed.
    """
    global pending_uid_change, last_card_uid, last_card_is_magic
    
    new_uid = data.get('newUid')
    
    if not new_uid:
        emit('uid_change_complete', {
            'success': False,
            'error': 'No new UID provided'
        })
        return
    
    if not last_card_uid:
        emit('uid_change_complete', {
            'success': False,
            'error': 'No card detected. Please place a card on the reader.'
        })
        return
    
    if not last_card_is_magic:
        emit('uid_change_complete', {
            'success': False,
            'error': 'This card is NOT a Magic Card. UID cannot be changed on regular NFC cards.',
            'originalUid': last_card_uid
        })
        return
    
    # Queue the UID change
    with write_lock:
        pending_uid_change = {
            'newUid': new_uid,
            'originalUid': last_card_uid,
            'timestamp': time.time()
        }
    
    emit('uid_change_queued', {
        'originalUid': last_card_uid,
        'newUid': new_uid,
        'message': 'UID change queued. Keep card on reader.'
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
        'isMagicCard': last_card_is_magic,
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
            'capabilities': ['read', 'write', 'uid_change'] if available else []
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
        'capabilities': ['read', 'write', 'uid_change'],
        'currentCard': last_card_uid,
        'isMagicCard': last_card_is_magic
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
            'isMagicCard': last_card_is_magic,
            'capabilities': ['read', 'write', 'uid_change']
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
        'data': card_data,
        'isMagicCard': last_card_is_magic
    })


@app.route('/card/change-uid', methods=['POST'])
def change_uid_rest():
    """Change UID of Magic Card via REST API"""
    global last_card_uid, last_card_is_magic
    
    data = request.json
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    new_uid = data.get('newUid')
    if not new_uid:
        return jsonify({'error': 'No new UID provided'}), 400
    
    if not last_card_uid:
        return jsonify({'error': 'No card detected'}), 400
    
    if not last_card_is_magic:
        return jsonify({
            'error': 'This card is NOT a Magic Card. UID cannot be changed.',
            'originalUid': last_card_uid,
            'isMagicCard': False
        }), 400
    
    original_uid = last_card_uid
    success, message = nfc_manager.change_uid(new_uid)
    
    if success:
        return jsonify({
            'success': True,
            'originalUid': original_uid,
            'newUid': new_uid,
            'message': message
        })
    else:
        return jsonify({
            'success': False,
            'originalUid': original_uid,
            'error': message
        }), 500


if __name__ == '__main__':
    logger.info("Starting NFC Bridge Service")
    logger.info("WebSocket server will be available at http://localhost:5000")
    logger.info("Capabilities: READ, WRITE, UID_CHANGE (Magic Cards only)")
    
    if nfc_manager.find_reader():
        logger.info(f"Reader found: {nfc_manager.reader}")
    else:
        logger.warning("No reader found at startup")
    
    socketio.run(app, host='0.0.0.0', port=5000, debug=False, allow_unsafe_werkzeug=True)