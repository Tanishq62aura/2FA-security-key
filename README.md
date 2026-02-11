<<<<<<< HEAD
# ESP32-S3 Offline TOTP Key

A secure, offline TOTP (Time-based One-Time Password) generator built on ESP32-S3 microcontroller. Features multi-account support, PIN-based locking, AES-CTR encrypted storage, USB HID keyboard emulation for typing OTPs, and a web-based management interface.

## Features

- **TOTP Generation**: Implements RFC 6238 TOTP using HMAC-SHA1
- **Multi-Account Support**: Store up to 10 TOTP accounts
- **Encrypted Storage**: AES-CTR encryption for account secrets in ESP32 NVS
- **PIN Lock**: 4-12 digit PIN with fail counter and lockout protection
- **USB HID**: Emulates USB keyboard to type OTPs directly into applications
- **Secure Time Sync**: HMAC-verified time synchronization over serial
- **Web UI**: HTML/CSS/JS interface for account management and device control
- **Serial API**: Python FastAPI server for communication with ESP32
- **Hardware Integration**: Button for manual OTP typing, LED status indicator

## Hardware Requirements

- ESP32-S3 microcontroller (tested with ESP32-S3-DevKitC-1)
- USB cable for programming and HID
- Optional: Push button and LED for hardware controls

## Software Dependencies

### ESP32 Firmware
- Arduino IDE 1.8+
- ESP32 core for Arduino (https://github.com/espressif/arduino-esp32)
- Required libraries (install via Arduino Library Manager):
  - USBHIDKeyboard
  - Preferences
  - Mbed TLS (for AES and SHA-256)

### Python Server
- Python 3.7+
- Required packages:
  ```
  pip install fastapi uvicorn pyserial
  ```

## Setup Instructions

### 1. ESP32 Firmware Setup

1. Install Arduino IDE and ESP32 core
2. Install required libraries via Library Manager
3. Open `ESP32_TOTP.ino` in Arduino IDE
4. Select ESP32-S3 board and appropriate COM port
5. Upload the sketch to your ESP32-S3

### 2. Python Server Setup

1. Install Python dependencies:
   ```bash
   pip install fastapi uvicorn pyserial
   ```

2. Run the server:
   ```bash
   python server.py
   ```

3. Open your browser to `http://localhost:8000`

### 3. Initial Configuration

1. Connect ESP32-S3 to your computer (it will appear as a serial device)
2. The web UI will automatically detect the ESP32
3. Set a PIN if desired (optional, device boots unlocked by default)
4. Sync time securely using the "Secure Sync Time" button
5. Add TOTP accounts using Base32 secrets from your authenticator apps

## Usage

### Web Interface

- **Status**: View current OTP, time sync status, and device lock state
- **Accounts**: Add, edit, delete, and switch between TOTP accounts
- **Sync Time**: Securely synchronize ESP32 clock with server time
- **Type OTP**: Send current OTP via USB HID keyboard
- **Lock/Unlock**: PIN-based device locking

### Hardware Controls

- **Button**: Long press (>600ms) to type current OTP (if unlocked)
- **LED**: 
  - Solid: Ready (synced + account active)
  - Fast blink: Not ready (no sync or no account)
  - Slow blink: Device locked

### Serial Commands

The ESP32 responds to various serial commands for integration:

- `TSYNC:<unix>:<nonce>:<hmac>` - Secure time sync
- `STATUS?` - Get device status
- `LISTACC` - List all accounts
- `SETACC:<idx>:<name>:<base32>` - Add/update account
- `SETACTIVE:<idx>` - Switch active account
- `TYPEOTP` - Type current OTP via HID
- `SETPIN:<pin>` - Set device PIN
- `UNLOCK:<pin>` - Unlock device

## Security Notes

- Account secrets are encrypted using AES-CTR with a key derived from ESP32's unique MAC address
- Time sync messages are HMAC-verified to prevent replay attacks
- PIN hashes use SHA-256 with random salt
- Device boots locked if PIN is set
- Failed PIN attempts are limited (max 5 before lockout)

## Configuration

### Sync Key
The HMAC key for time sync must match across all components. Default:
```
00112233445566778899AABBCCDDEEFF00112233
```

Update `SYNC_KEY_HEX` in:
- `ESP32_TOTP.ino`
- `server.py`
- `send_time_secure.py`

### Hardware Pins
Modify these in `ESP32_TOTP.ino` if needed:
```cpp
const int BUTTON_PIN = -1;  // -1 to disable
const int LED_PIN = LED_BUILTIN;
```

## Troubleshooting

- **ESP32 not detected**: Check serial port and VID/PID in `server.py`
- **Time not syncing**: Verify SYNC_KEY matches and serial connection is stable
- **HID not working**: Ensure ESP32 is connected via USB and recognized as keyboard
- **Accounts not saving**: Check NVS space and encryption key derivation

## Development

- `ESP32_TOTP.ino`: Main Arduino sketch
- `server.py`: FastAPI server for web UI and serial communication
- `send_time_secure.py`: Standalone time sync script
- `index.html`: Web interface

## License

This project is open-source. Use at your own risk.

## Contributing

Feel free to submit issues and pull requests for improvements.
=======
# 2fa-Key
>>>>>>> 8a4ac60c6199e0a29fc65c3e60f525e5ab0934ed
