# ESP32-S3 Offline TOTP Key

A secure, offline TOTP (Time-based One-Time Password) generator built on the ESP32-S3 microcontroller. Features multi-account support, PIN-based locking, AES-CTR encrypted storage, USB HID keyboard emulation for typing OTPs, ultra-low latency real-time synchronization, and a modern cyber-themed web management interface.

---

## Features

- **RFC 6238 TOTP Generation**: Standard 6-digit TOTP calculation using HMAC-SHA1 with 30-second rotating windows.
- **Multi-Account Storage**: Store and switch between up to 10 independent TOTP accounts on-device.
- **AES-CTR Encrypted Storage**: Account secrets are encrypted in ESP32 non-volatile storage (NVS) using keys derived from hardware-unique MAC attributes.
- **PIN Lockout Protection**: 4–12 digit security PIN with SHA-256 salted hashing and lockout protection after 5 failed attempts.
- **USB HID Keyboard Emulation**: Acts as a native USB keyboard to automatically type OTPs and press Enter into applications.
- **Secure Time Synchronization**: Replay-resistant serial time synchronization using random nonces and HMAC-SHA1 verification.
- **Instant Web Dashboard**: Fast HTML5/CSS3/JavaScript interface for account management, live countdown monitoring, and instant key injection.
- **High-Performance Serial API**: Python FastAPI backend with sub-15ms early-return response handling and serial adapter auto-detection.
- **Hardware Integration**: Onboard button trigger for manual OTP typing and multi-state RGB / LED status feedback.

---

## Hardware Requirements

- **ESP32-S3 Microcontroller** (e.g., ESP32-S3-DevKitC-1 or compatible module)
- **USB Cable(s)**:
  - **UART / COM port**: Used for flashing firmware and backend server communication.
  - **Native USB port**: Used for USB HID keyboard emulation to type OTPs directly into your computer.
- **Onboard BOOT Button**: Used to trigger OTP keyboard typing.
- **Status Indicator**: Onboard addressable RGB LED (or standard LED).

---

## Software Dependencies

### ESP32 Firmware
- **Arduino IDE 1.8+** or **Arduino IDE 2.x**
- **ESP32 Arduino Core** by Espressif (`https://raw.githubusercontent.com/espressif/arduino-esp32/gh-pages/package_esp32_index.json`)
- *Note:* All required firmware libraries (`USBHIDKeyboard`, `Preferences`, and `mbedtls`) are **built directly into the official ESP32 Arduino Core**. No external library installation is necessary.

### Python Backend Server
- **Python 3.7+**
- Required Python packages:
  ```bash
  pip install fastapi uvicorn pyserial
  ```

---

## Setup Instructions

### 1. ESP32 Firmware Flashing

1. Install the ESP32 core in Arduino IDE via **Tools > Board > Boards Manager**.
2. Open `ESP32_TOTP/ESP32_TOTP.ino` in Arduino IDE.
3. Select your ESP32-S3 board model from **Tools > Board > esp32 > ESP32S3 Dev Module**.
4. Enable USB mode in the Tools menu:
   - **USB CDC On Boot:** *Enabled*
   - **USB Mode:** *Hardware CDC and JTAG* (or *USB-OTG (TinyUSB)* depending on board setup)
5. Select the serial port for your ESP32-S3 and click **Upload**.

> **Note:** Close the Arduino IDE Serial Monitor after uploading, as the Python server requires exclusive serial access to communicate with the device.

---

### 2. Python Server Startup

1. Install the required Python libraries:
   ```bash
   pip install fastapi uvicorn pyserial
   ```

2. Start the FastAPI server:
   ```bash
   python server.py
   ```

3. Open your browser and navigate to:
   ```
   http://localhost:8000
   ```

---

## Web Dashboard & Credentials

### Default Credentials
* **User ID:** `admin`
* **Password:** `admin123`

### Dashboard Modes
* **Simulation Mode (Test Login):** Validates the credentials above, guides you through the hardware key 2FA challenge, and unlocks the secure TOTP vault.
* **Device Manager:** Allows immediate access to add new accounts, switch active accounts, delete accounts, configure PINs, and perform time synchronization without going through simulation login.
* **Demo Portal:** A lightweight standalone demonstration portal is available under the `demo/` directory (`demo/index.html`).

---

## Hardware Controls & Status

### Onboard Button
* **Press BOOT Button:** Types the active account's current 6-digit OTP followed by an `Enter` keystroke over USB HID (when device is unlocked).

### Status Feedback
* **RGB LED (Neopixel):**
  - **Dim Red:** Device connected but clock not synced or no account present.
  - **Blue:** Synced, active account loaded, and ready.
  - **Green Flash:** OTP successfully typed via USB keyboard.
* **Standard Single-Color LED:**
  - **Solid ON:** Synced and ready.
  - **Fast Blink:** Not synced or no active account.
  - **Slow Blink:** Device PIN-locked.

---

## Serial Command Interface

The ESP32 firmware accepts structured commands over serial:

| Command | Description |
| :--- | :--- |
| `STATUS?` | Queries lock status, sync state, active account, and current OTP with remaining seconds. |
| `TSYNC:<unix>:<nonce>:<hmac>` | Authenticated secure time synchronization with HMAC signature. |
| `LISTACC` | Lists all 10 on-device storage slots with account names and active flags. |
| `SETACC:<idx>:<name>:<base32>` | Injects a new Base32 secret key into the specified slot index (0–9). |
| `DELACC:<idx>` | Erases the account at the specified slot index. |
| `SETACTIVE:<idx>` | Sets the active account index for OTP generation and keyboard typing. |
| `NEXTACC` | Cycles to the next available account. |
| `CURRENTACC?` | Returns the currently active account name and slot index. |
| `TYPEOTP` | Commands the ESP32 to type the current OTP over USB HID keyboard. |
| `TYPEACCNAME` | Commands the ESP32 to type the active account name. |
| `TYPEALLACCOUNTS` | Types all stored account names and their current OTPs sequentially. |
| `SETPIN:<pin>` | Sets or updates the 4–12 digit security lock PIN. |
| `UNLOCK:<pin>` | Unlocks the device using the security PIN. |
| `LOCK` | Immediately locks the device, blocking OTP access until unlocked. |
| `LOCKED?` | Checks if the device is currently locked. |
| `PING` | Health check command; responds with `PONG`. |

---

## Security Architecture

- **Hardware-Tied Encryption**: Account secrets are encrypted with AES-CTR using a 256-bit key derived from the ESP32's unique factory eFuse MAC address. Stored secrets cannot be decrypted on another microcontroller.
- **Replay-Resistant Clock Sync**: Serial time sync packets include a 32-bit random nonce and HMAC-SHA1 signature verified against a shared secret key (`SYNC_KEY_HEX`).
- **PIN Salt & Hash**: Device PINs are stored as SHA-256 hashes salted with random hardware entropy (`esp_fill_random`).
- **Brute-Force Lockout**: After 5 consecutive invalid PIN attempts, the device locks out authentication attempts.

---

## Project Structure

```
2FA-security-key/
├── ESP32_TOTP/
│   └── ESP32_TOTP.ino       # Main Arduino sketch (TOTP, AES-CTR, USB HID)
├── demo/
│   ├── index.html           # Standalone demo authentication portal
│   ├── script.js            # Demo portal interactions
│   └── style.css            # Demo portal styling
├── index.html               # Main cyber-themed management dashboard
├── server.py                # FastAPI backend & serial communications layer
├── send_time_secure.py      # Standalone secure time-sync script
├── README.md                # Project documentation
└── .gitignore               # Ignored build and runtime artifacts
```

---

## Troubleshooting

- **Device Not Detected by Server:**
  - Verify that the ESP32-S3 is plugged into your computer and recognized in Device Manager.
  - Make sure the Arduino IDE Serial Monitor or any other terminal program is **closed**, as serial ports can only be accessed by one application at a time.
- **USB Keyboard Typing Not Working:**
  - Ensure your computer is connected to the ESP32-S3's **Native USB port** (USB-OTG), not exclusively the UART/Serial port.
  - Verify that your cursor or input field is focused on screen before triggering the BOOT button.
- **Time Not Syncing:**
  - Verify that `SYNC_KEY_HEX` matches between `ESP32_TOTP/ESP32_TOTP.ino`, `server.py`, and `send_time_secure.py`.

---

## License

This project is open-source. Use at your own risk.
