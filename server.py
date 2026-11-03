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
PREFERRED_PORT = "COM15"

ESP32_VID = 0x303A
ESP32_PID = 0x1001

SYNC_KEY_HEX = "00112233445566778899AABBCCDDEEFF00112233"

SERIAL_TIMEOUT = 0.08
COMMAND_TIMEOUT = 0.8

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
        # 1. Check preferred port if physically present
        if PREFERRED_PORT:
            for p in list_ports.comports():
                if p.device == PREFERRED_PORT:
                    return p.device
        # 2. Check VID / PID match
        for p in list_ports.comports():
            if p.vid == ESP32_VID and p.pid == ESP32_PID:
                return p.device
        # 3. Check common ESP32 / USB-serial chip descriptions
        for p in list_ports.comports():
            desc = (p.description or "").lower()
            if any(k in desc for k in ["esp32", "ch343", "ch340", "cp210", "ftdi"]):
                return p.device
        # 4. If only one serial port exists, use it
        ports = list_ports.comports()
        if len(ports) == 1:
            return ports[0].device
        return None

    def connect(self) -> None:
        if self.ser and self.ser.is_open:
            return

        port = self._find_port() or PREFERRED_PORT
        if not port:
            raise RuntimeError("ESP32 not found. Please connect your device.")

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

    def _get_serial(self) -> serial.Serial:
        self.connect()
        assert self.ser is not None
        return self.ser

    def send(self, cmd: str, wait: float = COMMAND_TIMEOUT, stop_on: Optional[List[str]] = None) -> List[str]:
        with self.lock:
            try:
                ser = self._get_serial()
                # Clear stale background broadcast lines from the input buffer
                ser.reset_input_buffer()

                ser.write((cmd + "\n").encode())
                ser.flush()

                end_time = time.time() + wait
                lines: List[str] = []

                while time.time() < end_time:
                    raw = ser.readline()
                    if not raw:
                        if lines and (not stop_on or time.time() + 0.1 >= end_time):
                            break
                        continue

                    txt = raw.decode(errors="ignore").strip("\x00\r\n ")
                    if len(txt) < 2:
                        continue
                    if txt.startswith(("READY", "TIME:")) and not cmd.startswith("TIME"):
                        continue

                    lines.append(txt)

                    # Return immediately as soon as expected termination marker is seen
                    if stop_on and any(s in txt for s in stop_on):
                        break

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

        resp = transport.send(
            f"TSYNC:{unix}:{nonce}:{mac}",
            wait=1.2,
            stop_on=["TSYNC_OK", "TSYNC_FAIL", "ERR:"]
        )
        return {"ok": any("TSYNC_OK" in r for r in resp), "raw": resp}

    def status(self) -> Dict[str, Any]:
        resp = transport.send(
            "STATUS?",
            wait=0.4,
            stop_on=["SECONDS_LEFT:", "ERR:LOCKED", "ACTIVE_ACC_PRESENT:NO", "SYNCED:NO"]
        )

        data: Dict[str, Any] = {
            "synced": False,
            "locked": False,
            "active_idx": None,
            "active_name": None,
            "now_unix": None,
            "current_otp": None,
            "seconds_left": None,
            "active_acc_present": False,
            "raw": resp,
        }
        for r in resp:
            if "ERR:LOCKED" in r:
                data["locked"] = True
            elif r.startswith("SYNCED:"):
                data["synced"] = "YES" in r
            elif r.startswith("ACTIVE_ACC_PRESENT:"):
                data["active_acc_present"] = "YES" in r
            elif r.startswith("ACTIVE_IDX:"):
                try:
                    data["active_idx"] = int(r.split(":", 1)[1])
                except (ValueError, IndexError):
                    pass
            elif r.startswith("ACTIVE_NAME:"):
                data["active_name"] = r.split(":", 1)[1].strip()
            elif r.startswith("NOW_UNIX:"):
                try:
                    data["now_unix"] = int(r.split(":", 1)[1])
                except (ValueError, IndexError):
                    pass
            elif r.startswith("CURRENT_OTP:"):
                data["current_otp"] = r.split(":", 1)[1].strip()
            elif r.startswith("SECONDS_LEFT:"):
                try:
                    data["seconds_left"] = int(r.split(":", 1)[1])
                except (ValueError, IndexError):
                    pass

        return data


    def accounts(self) -> List[Dict[str, str]]:
        resp = transport.send("LISTACC", wait=0.8, stop_on=["ACC:9", "ERR:"])
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
        resp = transport.send(f"SETACC:{idx}:{name}:{secret}", wait=1.2, stop_on=["ACC_SET_OK", "ERR:"])
        return {"ok": "ACC_SET_OK" in "".join(resp), "raw": resp}

    def set_active(self, idx: int) -> Dict[str, Any]:
        resp = transport.send(f"SETACTIVE:{idx}", wait=0.4, stop_on=["ACTIVE_SET_OK", "ERR:"])
        return {"ok": "ACTIVE_SET_OK" in "".join(resp)}

    def delete_account(self, idx: int) -> Dict[str, Any]:
        resp = transport.send(f"DELACC:{idx}", wait=0.4, stop_on=["ACC_DEL_OK", "ERR:"])
        return {"ok": "ACC_DEL_OK" in "".join(resp)}

    def set_pin(self, pin: str) -> Dict[str, Any]:
        resp = transport.send(f"SETPIN:{pin}", wait=0.4, stop_on=["PIN_SET_OK", "ERR:"])
        return {"ok": "PIN_SET_OK" in "".join(resp)}

    def unlock(self, pin: str) -> Dict[str, Any]:
        resp = transport.send(f"UNLOCK:{pin}", wait=0.5, stop_on=["UNLOCK_OK", "UNLOCK_FAIL", "ERR:"])
        return {"ok": "UNLOCK_OK" in "".join(resp)}

    def lock(self) -> Dict[str, Any]:
        resp = transport.send("LOCK", wait=0.4, stop_on=["LOCKED", "ERR:"])
        return {"ok": "LOCKED" in "".join(resp)}

    def type_otp(self) -> Dict[str, Any]:
        resp = transport.send("TYPEOTP", wait=0.5, stop_on=["TYPE_OTP_SENT", "ERR:"])
        return {"ok": "TYPE_OTP_SENT" in "".join(resp)}


svc = ESP32Service()

# =====================
# FASTAPI
# =====================
app = FastAPI(title="ESP32 Offline 2FA Server")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

def response(data: Dict[str, Any]) -> JSONResponse:
    data["connection"] = transport.info()
    return JSONResponse(data)

@app.get("/")
def ui():
    return FileResponse("index.html")

@app.get("/api/status")
def api_status():
    try:
        return response({"ok": True, "status": svc.status()})
    except Exception as e:
        return response({
            "ok": False,
            "error": str(e),
            "status": {
                "synced": False,
                "locked": True,
                "active_acc_present": False,
                "active_name": None,
                "current_otp": None,
                "seconds_left": None,
                "error": str(e),
            }
        })

@app.post("/api/sync")
def api_sync():
    try:
        return response(svc.sync_time())
    except Exception as e:
        return response({"ok": False, "error": str(e)})

@app.get("/api/accounts")
def api_accounts():
    try:
        return response({"ok": True, "accounts": svc.accounts()})
    except Exception as e:
        return response({"ok": False, "error": str(e), "accounts": []})

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

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="127.0.0.1", port=8000)
