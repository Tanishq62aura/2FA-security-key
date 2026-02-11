# send_time_secure.py
import time
import hmac
import hashlib
import serial

# Change this if your COM port is different.
SERIAL_PORT = "COM10"
BAUD_RATE = 115200

# MUST MATCH firmware
SYNC_KEY_HEX = "00112233445566778899AABBCCDDEEFF00112233"


def build_tsync_line() -> str:
    unix_time = int(time.time())

    # 32-bit random nonce
    nonce_int = int.from_bytes(
        hashlib.sha1(str(time.time()).encode()).digest()[:4], "big"
    )
    nonce_hex = f"{nonce_int:08X}"

    msg = f"{unix_time}:{nonce_hex}".encode("utf-8")
    key = bytes.fromhex(SYNC_KEY_HEX)
    mac = hmac.new(key, msg, hashlib.sha1).hexdigest().upper()

    return f"TSYNC:{unix_time}:{nonce_hex}:{mac}\n"


def main():
    line = build_tsync_line()
    print(f"Opening port {SERIAL_PORT} at {BAUD_RATE}...")

    ser = serial.Serial(SERIAL_PORT, BAUD_RATE, timeout=2)

    time.sleep(1)

    # Clean stale junk coming from ESP32 boot logs
    ser.reset_input_buffer()
    ser.reset_output_buffer()

    print("Sending:", line.strip())
    ser.write(line.encode("utf-8"))
    ser.flush()

    print("\nESP32 Response:")
    for _ in range(25):
        resp = ser.readline().decode(errors="ignore").strip()
        if resp:
            print(">>", resp)
            # Stop early if success detected
            if "TSYNC_OK" in resp or "TIME_SYNC_OK" in resp:
                break

    ser.close()
    print("\n✓ TIME SYNC COMPLETE")


if __name__ == "__main__":
    main()
