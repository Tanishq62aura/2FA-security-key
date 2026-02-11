import time
import hmac
import hashlib
import threading
from typing import Optional, List, Dict, Any

import serial
from serial.tools import list_ports
from fastapi import FastAPI
from fastapi.responses import JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware

# =====================
# CONFIG
# =====================
BAUD_RATE = 115200
PREFERRED_PORT = "COM10" # Set to None to auto-detect 

ESP32_VID = 0x303A
ESP32_PID = 0x1001

SYNC_KEY_HEX = "00112233445566778899AABBCCDDEEFF00112233"

SERIAL_TIMEOUT = 1
COMMAND_TIMEOUT = 2.5

# =====================
# SERIAL TRANSPORT
# =====================
class SerialTransport:
    def __init__(self) -> None:
        self.ser: Optional[serial.Serial] = None
        self.port: Optional[str] = None
        self.lock = threading.Lock()
        self.last_error: Optional[str] = None

    def _find_port(self) -> Optional[str]:
        for p in list_ports.comports():
            if p.vid == ESP32_VID and p.pid == ESP32_PID:
                return p.device
        for p in list_ports.comports():
            if "esp32" in (p.description or "").lower():
                return p.device
        return None

    def connect(self) -> None:
        if self.ser and self.ser.is_open:
            return

        port = PREFERRED_PORT or self._find_port()
        if not port:
            raise RuntimeError("ESP32 not found")

        self.ser = serial.Serial(
            port,
            BAUD_RATE,
            timeout=SERIAL_TIMEOUT,
        )
        time.sleep(0.4)
        self.port = port
        self.last_error = None

    def disconnect(self) -> None:
        if self.ser:
            try:
                self.ser.close()
            except Exception:
                pass
        self.ser = None
        self.port = None

    # 🔑 THIS IS THE CRITICAL FIX
    def _get_serial(self) -> serial.Serial:
        self.connect()
        assert self.ser is not None
        return self.ser

    def send(self, cmd: str, wait: float = COMMAND_TIMEOUT) -> List[str]:
        with self.lock:
            try:
                ser = self._get_serial()

                ser.write((cmd + "\n").encode())
                ser.flush()

                end_time = time.time() + wait
                lines: List[str] = []

                while time.time() < end_time:
                    raw = ser.readline()
                    if not raw:
                        continue

                    txt = raw.decode(errors="ignore").strip("\x00\r\n ")
                    if len(txt) < 3:
                        continue
                    if txt.startswith(("READY", "TIME:", "STATUS:")):
                        continue

                    lines.append(txt)

                return lines

            except Exception as e:
                self.last_error = str(e)
                self.disconnect()
                raise

    def info(self) -> Dict[str, Any]:
        return {
            "connected": self.ser is not None and self.ser.is_open,
            "port": self.port,
            "last_error": self.last_error,
        }


transport = SerialTransport()

# =====================
# COMMAND LAYER
# =====================
class ESP32Service:
    def sync_time(self) -> Dict[str, Any]:
        unix = int(time.time())
        nonce = hashlib.sha1(str(time.time()).encode()).digest()[:4].hex().upper()

        msg = f"{unix}:{nonce}".encode()
        key = bytes.fromhex(SYNC_KEY_HEX)
        mac = hmac.new(key, msg, hashlib.sha1).hexdigest().upper()

        resp = transport.send(f"TSYNC:{unix}:{nonce}:{mac}", wait=3)
        return {"ok": any("TSYNC_OK" in r for r in resp), "raw": resp}

    def status(self) -> Dict[str, Any]:
        resp = transport.send("STATUS?")

        data: Dict[str, Any] = {
            "synced": False,
            "locked": True,
            "active_idx": None,
            "active_name": None,
            "now_unix": None,
            "current_otp": None,
            "seconds_left": None,
            "raw": resp,
        }
        for r in resp:
            if r.startswith("SYNCED:"):
                data["synced"] = "YES" in r

            elif r.startswith("ACTIVE_IDX:"):
                data["active_idx"] = int(r.split(":", 1)[1])

            elif r.startswith("ACTIVE_NAME:"):
                data["active_name"] = r.split(":", 1)[1].strip()
            elif r.startswith("NOW_UNIX:"):
                data["now_unix"] = int(r.split(":", 1)[1])
            elif r.startswith("CURRENT_OTP:"):
                data["current_otp"] = r.split(":", 1)[1].strip()

            elif r.startswith("SECONDS_LEFT:"):
                data["seconds_left"] = int(r.split(":", 1)[1])

        lock = transport.send("LOCKED?")
        for r in lock:
            if r.startswith("LOCKED:"):
                data["locked"] = "YES" in r

        return data


    def accounts(self) -> List[Dict[str, str]]:
        resp = transport.send("LISTACC")
        accs: List[Dict[str, str]] = []

        for r in resp:
            if not r.startswith("ACC:"):
                continue

            obj: Dict[str, str] = {}
            for p in r.split():
                if ":" in p:
                    k, v = p.split(":", 1)
                    obj[k.lower()] = v

            accs.append(obj)

        return accs

    def set_account(self, idx: int, name: str, secret: str) -> Dict[str, Any]:
        resp = transport.send(f"SETACC:{idx}:{name}:{secret}", wait=3)
        return {"ok": "ACC_SET_OK" in "".join(resp), "raw": resp}

    def set_active(self, idx: int) -> Dict[str, Any]:
        resp = transport.send(f"SETACTIVE:{idx}")
        return {"ok": "ACTIVE_SET_OK" in "".join(resp)}

    def delete_account(self, idx: int) -> Dict[str, Any]:
        resp = transport.send(f"DELACC:{idx}")
        return {"ok": "ACC_DEL_OK" in "".join(resp)}

    def set_pin(self, pin: str) -> Dict[str, Any]:
        resp = transport.send(f"SETPIN:{pin}")
        return {"ok": "PIN_SET_OK" in "".join(resp)}

    def unlock(self, pin: str) -> Dict[str, Any]:
        resp = transport.send(f"UNLOCK:{pin}")
        return {"ok": "UNLOCK_OK" in "".join(resp)}

    def lock(self) -> Dict[str, Any]:
        resp = transport.send("LOCK")
        return {"ok": "LOCKED" in "".join(resp)}

    def type_otp(self) -> Dict[str, Any]:
        resp = transport.send("TYPEOTP")
        return {"ok": "TYPE_OTP_SENT" in "".join(resp)}


svc = ESP32Service()

# =====================
# FASTAPI
# =====================
app = FastAPI(title="ESP32 Offline 2FA Server")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost", "http://127.0.0.1"],
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Content-Type"],
)

def response(data: Dict[str, Any]) -> JSONResponse:
    data["connection"] = transport.info()
    return JSONResponse(data)

@app.get("/")
def ui():
    return FileResponse("index.html")

@app.get("/api/status")
def api_status():
    return response({"ok": True, "status": svc.status()})

@app.post("/api/sync")
def api_sync():
    return response(svc.sync_time())

@app.get("/api/accounts")
def api_accounts():
    return response({"ok": True, "accounts": svc.accounts()})

@app.post("/api/account")
def api_set_account(body: Dict[str, Any]):
    return response(
        svc.set_account(int(body["index"]), body["name"], body["secret"])
    )

@app.delete("/api/account/{idx}")
def api_delete_account(idx: int):
    return response(svc.delete_account(idx))

@app.post("/api/active")
def api_set_active(body: Dict[str, Any]):
    return response(svc.set_active(int(body["index"])))

@app.post("/api/set-pin")
def api_set_pin(body: Dict[str, Any]):
    return response(svc.set_pin(body["pin"]))

@app.post("/api/unlock")
def api_unlock(body: Dict[str, Any]):
    return response(svc.unlock(body["pin"]))

@app.post("/api/lock")
def api_lock():
    return response(svc.lock())

@app.post("/api/type-otp")
def api_type_otp():
    return response(svc.type_otp())
