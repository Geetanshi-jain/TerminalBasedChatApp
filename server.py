# server.py (final, working)
import socket
import threading
import json
from typing import Dict
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

HOST = '127.0.0.1'
PORT = 12346

# Hardcoded users
USERS: Dict[str, str] = {
    "alice": "alicepass",
    "bob": "bobpass",
    "charlie": "charliepass"
}

LOGIN_KEY = b'loginsecretkey12'   # 16 bytes

# Channels (same keys must be in client)
CHANNELS: Dict[str, Dict] = {
    "channel1": {"key": b'generalchannelk1', "members": set(), "history": []},
    "channel2": {"key": b'devchannelkey123', "members": set(), "history": []},
    "channel3": {"key": b'secretchannelkey', "members": set(), "history": []},
}

username_to_conn: Dict[str, socket.socket] = {}
conn_to_username: Dict[socket.socket, str] = {}

map_lock = threading.Lock()
channels_lock = threading.Lock()

def aes_decrypt(key: bytes, iv: bytes, ct: bytes) -> str:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size).decode()

def send_json(conn: socket.socket, obj: dict):
    try:
        conn.sendall(json.dumps(obj).encode('utf-8'))
    except Exception:
        pass

def safe_recv_json(conn: socket.socket, bufsize: int = 8192):
    data = conn.recv(bufsize)
    if not data:
        raise ValueError("peer closed")
    text = data.decode('utf-8', errors='ignore').strip()
    if not text:
        raise ValueError("empty")
    return json.loads(text)

def broadcast_to_channel(channel: str, msg_obj: dict):
    with channels_lock:
        members = set(CHANNELS[channel]["members"])
    with map_lock:
        conns = [username_to_conn[u] for u in members if u in username_to_conn]
    for c in conns:
        try:
            c.sendall(json.dumps(msg_obj).encode('utf-8'))
        except:
            pass

def cleanup_conn(conn: socket.socket):
    with map_lock:
        uname = conn_to_username.pop(conn, None)
        if uname and username_to_conn.get(uname) is conn:
            username_to_conn.pop(uname, None)
    if uname:
        with channels_lock:
            for ch in CHANNELS.values():
                ch["members"].discard(uname)
        print(f"[INFO] {uname} disconnected and removed from channels")
    try: conn.close()
    except: pass

def handle_client(conn: socket.socket, addr):
    print(f"[INFO] Connection from {addr}")
    try:
        # ---- LOGIN ----
        login_obj = safe_recv_json(conn, bufsize=2048)
        uname = login_obj.get("username")
        payload = login_obj.get("payload", {})
        iv = bytes.fromhex(payload["iv"])
        ct = bytes.fromhex(payload["ct"])
        password = aes_decrypt(LOGIN_KEY, iv, ct)

        if USERS.get(uname) != password:
            send_json(conn, {"type":"login","status":"fail","reason":"invalid-creds"})
            return
        with map_lock:
            username_to_conn[uname] = conn
            conn_to_username[conn] = uname
        send_json(conn, {"type":"login","status":"ok"})
        print(f"[INFO] {uname} logged in")

        # ---- MAIN LOOP ----
        while True:
            msg_obj = safe_recv_json(conn)
            mode = msg_obj.get("mode")

            if mode == "join":
                channel = msg_obj.get("channel")
                provided = msg_obj.get("key", "").encode()
                if channel in CHANNELS and provided == CHANNELS[channel]["key"]:
                    with channels_lock:
                        CHANNELS[channel]["members"].add(uname)
                        history_copy = list(CHANNELS[channel]["history"])
                    send_json(conn, {"mode":"join_response","status":"ok","channel":channel,"items":history_copy})
                    print(f"[INFO] {uname} joined {channel}")
                else:
                    send_json(conn, {"mode":"join_response","status":"fail"})
                continue

            if mode == "channel":
                channel = msg_obj.get("channel")
                if channel not in CHANNELS: continue
                with channels_lock:
                    if uname not in CHANNELS[channel]["members"]:
                        continue
                    CHANNELS[channel]["history"].append({"from": uname, "payload": msg_obj["payload"]})
                broadcast_to_channel(channel, msg_obj)
                continue

            if mode in ("direct","p2p"):
                to_user = msg_obj.get("to")
                with map_lock:
                    dest = username_to_conn.get(to_user)
                if dest:
                    dest.sendall(json.dumps(msg_obj).encode())
                continue

    except Exception as e:
        print(f"[ERROR] {addr}: {e}")
    finally:
        cleanup_conn(conn)

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(50)
    print(f"[INFO] Server listening {HOST}:{PORT}")
    try:
        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle_client,args=(conn,addr),daemon=True).start()
    except KeyboardInterrupt:
        print("Shutting down server")
    finally:
        s.close()

if __name__ == "__main__":
    main()
