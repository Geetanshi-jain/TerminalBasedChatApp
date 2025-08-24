import socket
import threading
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from colorama import Fore, Style
import sys

# ----------------- CONFIG -----------------
HOST = '127.0.0.1'
PORT = 12346

LOGIN_KEY = b'loginsecretkey12'
CHANNEL_KEY = b'shdhubsdafb12346'    # server.py ke saath match karo

USERNAME = input("Enter username: ")
PASSWORD = input("Enter password: ")

# Fixed colors for 3 users
colors = {"alice": Fore.GREEN, "bob": Fore.BLUE, "charlie": Fore.MAGENTA}
MY_COLOR = colors.get(USERNAME, Fore.WHITE)

# ----------------- AES -----------------
def aes_encrypt(key, plaintext: str):
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return iv, ct

def aes_decrypt(key, iv: bytes, ct: bytes) -> str:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode()

# ----------------- LOGIN -----------------
def login(sock):
    iv, ct = aes_encrypt(LOGIN_KEY, PASSWORD)
    login_obj = {"username": USERNAME, "payload": {"iv": iv.hex(), "ct": ct.hex()}}
    sock.sendall(json.dumps(login_obj).encode())
    resp_raw = sock.recv(2048).decode()
    try:
        resp = json.loads(resp_raw)
    except:
        print(f"{Fore.RED}[ERROR] Bad login response{Style.RESET_ALL}")
        sys.exit(1)

    if resp.get("status") == "ok":
        print(f"{Fore.YELLOW}[INFO] Login successful{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}[ERROR] Login failed: {resp.get('reason')}{Style.RESET_ALL}")
        sys.exit(1)

# ----------------- RECEIVE -----------------
def receive(sock):
    """Background thread to receive and display messages."""
    while True:
        try:
            data = sock.recv(8192)
            if not data:
                break
            try:
                msg_obj = json.loads(data.decode())
            except:
                continue

            mode = msg_obj.get("mode")
            sender = msg_obj.get("from", "unknown")
            payload = msg_obj.get("payload", {})

            if "iv" in payload and "ct" in payload:
                try:
                    iv = bytes.fromhex(payload["iv"])
                    ct = bytes.fromhex(payload["ct"])
                    pt = aes_decrypt(CHANNEL_KEY, iv, ct)
                except Exception:
                    pt = "[decryption error]"
            else:
                pt = ""

            color = colors.get(sender, Fore.WHITE)

            if mode == "channel":
                print(f"{color}[CHANNEL][{sender}]: {pt}{Style.RESET_ALL}")
            elif mode == "direct":
                print(f"{color}[DM][{sender} -> you]: {pt}{Style.RESET_ALL}")
            elif mode == "p2p":
                print(f"{color}[P2P][{sender} <-> you]: {pt}{Style.RESET_ALL}")
            elif mode == "channel_history_response":
                print(f"{Fore.YELLOW}[INFO] Channel history:{Style.RESET_ALL}")
                for item in msg_obj.get("items", []):
                    s = item.get("from", "?")
                    p = item.get("payload", {})
                    try:
                        iv = bytes.fromhex(p["iv"])
                        ct = bytes.fromhex(p["ct"])
                        pt = aes_decrypt(CHANNEL_KEY, iv, ct)
                    except Exception:
                        pt = "[error]"
                    c = colors.get(s, Fore.WHITE)
                    print(f"{c}[CHANNEL][{s}]: {pt}{Style.RESET_ALL}")

        except Exception:
            break

# ----------------- SEND -----------------
def send_messages(sock):
    """Main loop for sending messages / selecting modes."""
    while True:
        try:
            print("\nOptions:\n1. Join channel\n2. Direct message\n3. Point-to-point chat\n4. Quit")
            choice = input("Enter choice: ").strip()

            if choice == "1":
                secret = input("Enter channel secret key: ")
                if secret.encode() == CHANNEL_KEY:
                    # Request history from server
                    sock.sendall(json.dumps({"mode": "channel_history_request"}).encode())
                    print(f"{Fore.YELLOW}[INFO] Entering channel chat (Ctrl+C to exit){Style.RESET_ALL}")
                    while True:
                        try:
                            msg = input()
                            if msg.strip().lower() == "/exit":
                                print(f"{Fore.YELLOW}Exiting channel chat{Style.RESET_ALL}")
                                break
                            iv, ct = aes_encrypt(CHANNEL_KEY, msg)
                            msg_obj = {"mode": "channel", "from": USERNAME, "payload": {"iv": iv.hex(), "ct": ct.hex()}}
                            sock.sendall(json.dumps(msg_obj).encode())
                        except KeyboardInterrupt:
                            print(f"{Fore.YELLOW}\nExiting channel chat{Style.RESET_ALL}")
                            break
                else:
                    print(f"{Fore.RED}Wrong channel key!{Style.RESET_ALL}")

            elif choice == "2":
                to_user = input("Send to (username): ")
                print(f"{Fore.YELLOW}[INFO] Direct chat with {to_user} (type /exit to stop){Style.RESET_ALL}")
                while True:
                    msg = input()
                    if msg.strip().lower() == "/exit":
                        break
                    iv, ct = aes_encrypt(CHANNEL_KEY, msg)
                    msg_obj = {"mode": "direct", "from": USERNAME, "to": to_user,
                               "payload": {"iv": iv.hex(), "ct": ct.hex()}}
                    sock.sendall(json.dumps(msg_obj).encode())

            elif choice == "3":
                to_user = input("Enter username for point-to-point chat: ")
                print(f"{Fore.YELLOW}[INFO] P2P chat with {to_user} (type /exit to stop){Style.RESET_ALL}")
                while True:
                    msg = input()
                    if msg.strip().lower() == "/exit":
                        break
                    iv, ct = aes_encrypt(CHANNEL_KEY, msg)
                    msg_obj = {"mode": "p2p", "from": USERNAME, "to": to_user,
                               "payload": {"iv": iv.hex(), "ct": ct.hex()}}
                    sock.sendall(json.dumps(msg_obj).encode())

            elif choice == "4":
                print(f"{Fore.YELLOW}Goodbye!{Style.RESET_ALL}")
                sock.close()
                sys.exit(0)
            else:
                print("Invalid choice.")

        except KeyboardInterrupt:
            print(f"{Fore.YELLOW}\n[INFO] Quitting client{Style.RESET_ALL}")
            sock.close()
            sys.exit(0)

# ----------------- MAIN -----------------
def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))
    login(sock)
    threading.Thread(target=receive, args=(sock,), daemon=True).start()
    send_messages(sock)

if __name__ == "__main__":
    main()
