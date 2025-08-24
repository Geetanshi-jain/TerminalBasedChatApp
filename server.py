# server.py
# Robust multi-client chat server with:
# - login (encrypted password using LOGIN_KEY)
# - direct / p2p / channel messaging (server forwards ciphertext only)
# - channel history storage (ciphertexts)
# - safe recv + timeouts + graceful cleanup
#
# NOTE: Server DOES NOT decrypt channel/chat messages (only login is decrypted).
# Clients must hold CHANNEL_KEY / per-pair keys to decrypt messages.

import socket
import threading
import json
from typing import Dict, List
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# ----------------- CONFIG -----------------
HOST = '127.0.0.1'
PORT = 12346

# Hardcoded users: username -> plaintext password (for demo)
USERS: Dict[str, str] = {
    "alice": "alicepass",
    "bob": "bobpass",
    "charlie": "charliepass"
}

# AES key used to encrypt login password payload (clients must use same key)
LOGIN_KEY = b'loginsecretkey12'   # 16 bytes (AES-128) - demo only

# Channel key (clients must have this to decrypt channel messages)
CHANNEL_KEY = b'shdhubsdafb12346'   # 14 bytes here -> make sure clients use same length/key. Prefer 16/32 bytes.

# ----------------- Shared state -----------------
# username -> socket
username_to_conn: Dict[str, socket.socket] = {}
# socket -> username
conn_to_username: Dict[socket.socket, str] = {}
# channel history: list of dicts {"from": username, "payload": {"iv": "...", "ct": "..."}}
channel_messages: List[Dict] = []

# Locks for thread-safety
map_lock = threading.Lock()
history_lock = threading.Lock()

# ----------------- AES helper (login decrypt) -----------------
def aes_decrypt(key: bytes, iv: bytes, ct: bytes) -> str:
    """Decrypt AES-CBC ciphertext and return plaintext string."""
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode()

# ----------------- Networking helpers -----------------
def send_json(conn: socket.socket, obj: dict):
    """Send JSON object as one frame (utf-8)."""
    try:
        conn.sendall(json.dumps(obj).encode('utf-8'))
    except Exception:
        # ignore; caller handles cleanup
        pass

def safe_recv_json(conn: socket.socket, bufsize: int = 8192):
    """
    Receive one JSON object. This expects the client to send one JSON per send.
    Returns parsed dict on success.
    Raises:
      ValueError on peer closed / bad data
      TimeoutError on socket timeout (caller may continue)
    """
    try:
        data = conn.recv(bufsize)
        if not data:
            raise ValueError("peer closed")
        text = data.decode('utf-8', errors='ignore').strip()
        if not text:
            raise ValueError("empty")
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            # bad frame; caller can decide to ignore
            raise ValueError("bad json")
    except socket.timeout:
        raise TimeoutError
    except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
        raise ValueError("peer reset")

def forward_to_user(username: str, msg_obj: dict):
    """Send msg_obj to a specific connected user if present."""
    with map_lock:
        dest = username_to_conn.get(username)
    if not dest:
        return
    try:
        dest.sendall(json.dumps(msg_obj).encode('utf-8'))
    except Exception:
        # ignore; handler will cleanup later
        pass

def broadcast_all(msg_obj: dict):
    """Broadcast msg_obj to all connected users (best-effort)."""
    with map_lock:
        conns = list(username_to_conn.values())
    payload = json.dumps(msg_obj).encode('utf-8')
    for c in conns:
        try:
            c.sendall(payload)
        except Exception:
            # ignore failures here
            pass

def cleanup_conn(conn: socket.socket):
    """Remove mappings and close socket for a connection."""
    with map_lock:
        user = conn_to_username.pop(conn, None)
        if user and username_to_conn.get(user) is conn:
            username_to_conn.pop(user, None)
    try:
        conn.close()
    except Exception:
        pass
    if user:
        print(f"[INFO] {user} disconnected")

# ----------------- Client handler -----------------
def handle_client(conn: socket.socket, addr):
    print(f"[INFO] Connection from {addr}")
    conn.settimeout(6.0)  # periodic timeout so thread can check loop conditions
    username = None
    try:
        # ---------------- LOGIN PHASE ----------------
        try:
            login_obj = safe_recv_json(conn, bufsize=2048)
        except TimeoutError:
            send_json(conn, {"type": "login", "status": "fail", "reason": "timeout"})
            return
        except ValueError:
            send_json(conn, {"type": "login", "status": "fail", "reason": "bad-frame"})
            return

        # Expecting: {"username": "...", "payload": {"iv":"hex", "ct":"hex"}}
        payload = login_obj.get("payload", {})
        uname = login_obj.get("username")
        if not uname or "iv" not in payload or "ct" not in payload:
            send_json(conn, {"type": "login", "status": "fail", "reason": "invalid-fields"})
            return

        # decrypt password using LOGIN_KEY
        try:
            iv = bytes.fromhex(payload["iv"])
            ct = bytes.fromhex(payload["ct"])
            password = aes_decrypt(LOGIN_KEY, iv, ct)
        except Exception:
            send_json(conn, {"type": "login", "status": "fail", "reason": "decrypt-failed"})
            return

        # verify
        if uname in USERS and USERS[uname] == password:
            send_json(conn, {"type": "login", "status": "ok"})
            with map_lock:
                username_to_conn[uname] = conn
                conn_to_username[conn] = uname
            username = uname
            print(f"[INFO] {username} logged in from {addr}")
        else:
            send_json(conn, {"type": "login", "status": "fail", "reason": "invalid-creds"})
            return

        # ---------------- MESSAGE LOOP ----------------
        while True:
            try:
                msg_obj = safe_recv_json(conn)
            except TimeoutError:
                # no data this interval, continue waiting
                continue
            except ValueError:
                # peer closed or bad frame -> exit loop
                break

            # Expected message types:
            # - direct: {"mode":"direct","from":..., "to":..., "payload": {...}}
            # - p2p: same as direct
            # - channel: {"mode":"channel","from":..., "payload": {...}}
            # - channel_history_request: {"mode":"channel_history_request"}
            mode = msg_obj.get("mode")

            if mode == "direct" or mode == "p2p":
                to_user = msg_obj.get("to")
                if not to_user:
                    # ignore malformed
                    continue
                forward_to_user(to_user, msg_obj)

            elif mode == "channel":
                # store ciphertext (server does not decrypt message)
                item = {"from": msg_obj.get("from", "?"), "payload": msg_obj.get("payload", {})}
                with history_lock:
                    channel_messages.append(item)
                # broadcast to all connected users
                broadcast_all(msg_obj)

            elif mode == "channel_history_request":
                # send stored channel messages (ciphertext objects)
                with history_lock:
                    history_copy = list(channel_messages)
                resp = {"mode": "channel_history_response", "items": history_copy}
                send_json(conn, resp)

            else:
                # unknown mode - optionally inform client
                send_json(conn, {"type": "error", "reason": "unknown-mode"})
                continue

    except Exception as e:
        print(f"[ERROR] handler for {addr}: {e}")
    finally:
        cleanup_conn(conn)

# ----------------- MAIN -----------------
def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(20)
    print(f"[INFO] Server listening on {HOST}:{PORT}")

    try:
        while True:
            conn, addr = server.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()
    except KeyboardInterrupt:
        print("\n[INFO] Server shutting down (KeyboardInterrupt)")
    finally:
        # close all client sockets
        with map_lock:
            conns = list(username_to_conn.values())
        for c in conns:
            try:
                c.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                c.close()
            except Exception:
                pass
        server.close()

if __name__ == "__main__":
    main()