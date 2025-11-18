# USB NFC Bridge Service

## What's Included

1. **app.py** - The bridge service
2. **requirements.txt** - Python dependencies
3. **test.html** - Visual test interface (RECOMMENDED)

## Quick Start (3 Steps)

### Step 1: Install Dependencies (One-time)

**Windows:**
```cmd
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

**Linux/Mac:**
```bash
# Install system dependencies (one-time)
sudo apt-get install pcscd pcsc-tools  # Linux only
sudo systemctl start pcscd              # Linux only

# Install Python packages
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Step 2: Connect ACR1222L Reader

1. Plug USB NFC reader into your computer
2. Wait for driver installation (automatic on most systems)

### Step 3: Run Bridge Service

```bash
python app.py
```

**You should see:**
```
INFO - Starting NFC Bridge Service
INFO - Reader found: ACS ACR1222L PICC Reader 00 00
INFO - WebSocket server will be available at http://localhost:5000
 * Running on http://0.0.0.0:5000
```

## 🧪 Testing

1. Keep bridge service running
2. Open `test.html` in any browser
3. You'll see a interface with:
   - Connection status (should be green)
   - "Start Scanning" button
   - Card display area
   - Activity log

4. Click "Start Scanning"
5. Place NFC card on reader
6. **Card ID will appear**


## Success Indicators

When you place an NFC card on the reader:

### In test.html:
- 🎉 Card ID appears (e.g., `04:A1:B2:C3:D4:E5:F6`)
- Activity log shows "CARD DETECTED"

### In bridge service terminal:
```
INFO - Card detected: 04:A1:B2:C3:D4:E5:F6
```

## Troubleshooting

### "No card readers found"
- Check USB cable connection
- Windows: Look in Device Manager → Smart card readers
- Linux: Run `pcsc_scan` to verify reader