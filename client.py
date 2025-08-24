# client.py (final, working)
import socket, threading, json, sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from colorama import Fore, Style

HOST, PORT = '127.0.0.1', 12346
LOGIN_KEY = b'loginsecretkey12'

# Must match server
CHANNEL_KEYS = {
    "channel1": b'generalchannelk1',
    "channel2": b'devchannelkey123',
    "channel3": b'secretchannelkey'
}

USERNAME = input("Enter username: ")
PASSWORD = input("Enter password: ")

colors = {"alice":Fore.GREEN,"bob":Fore.BLUE,"charlie":Fore.MAGENTA}
MY_COLOR = colors.get(USERNAME, Fore.WHITE)

def aes_encrypt(key, plaintext):
    iv = get_random_bytes(16)
    cipher = AES.new(key,AES.MODE_CBC,iv)
    return iv, cipher.encrypt(pad(plaintext.encode(),AES.block_size))

def aes_decrypt(key, iv, ct):
    cipher = AES.new(key,AES.MODE_CBC,iv)
    return unpad(cipher.decrypt(ct),AES.block_size).decode()

def login(sock):
    iv, ct = aes_encrypt(LOGIN_KEY,PASSWORD)
    sock.sendall(json.dumps({"username":USERNAME,"payload":{"iv":iv.hex(),"ct":ct.hex()}}).encode())
    resp = json.loads(sock.recv(2048).decode())
    if resp.get("status")!="ok":
        print("Login failed",resp); sys.exit(1)
    print(f"{Fore.YELLOW}[INFO] Login successful{Style.RESET_ALL}")

def receive(sock):
    while True:
        try:
            data=sock.recv(8192)
            if not data: break
            msg=json.loads(data.decode())
            mode=msg.get("mode"); sender=msg.get("from","?")
            payload=msg.get("payload",{}); pt=""
            if "iv" in payload:
                ch=msg.get("channel")
                if ch in CHANNEL_KEYS:
                    try: pt=aes_decrypt(CHANNEL_KEYS[ch],bytes.fromhex(payload["iv"]),bytes.fromhex(payload["ct"]))
                    except: pt="[decrypt-error]"
            color=colors.get(sender,Fore.WHITE)
            if mode=="channel":
                print(f"{color}[{msg['channel']}][{sender}]: {pt}{Style.RESET_ALL}")
            elif mode=="direct":
                print(f"{color}[DM {sender}]: {pt}{Style.RESET_ALL}")
            elif mode=="p2p":
                print(f"{color}[P2P {sender}]: {pt}{Style.RESET_ALL}")
            elif mode=="join_response":
                if msg.get("status")=="ok":
                    ch=msg["channel"]; print(f"{Fore.YELLOW}[INFO] Joined {ch}{Style.RESET_ALL}")
                    for it in msg["items"]:
                        s=it["from"]; p=it["payload"]
                        try: h=aes_decrypt(CHANNEL_KEYS[ch],bytes.fromhex(p["iv"]),bytes.fromhex(p["ct"]))
                        except: h="[error]"
                        print(f"{colors.get(s,Fore.WHITE)}[{ch}][{s}]: {h}{Style.RESET_ALL}")
        except: break

def send_messages(sock):
    while True:
        print("\n1.Join channel\n2.Direct message\n3.P2P\n4.Quit")
        ch=input("Choice: ")
        if ch=="1":
            channel=input("Channel: ").strip()
            if channel not in CHANNEL_KEYS: print("Unknown"); continue
            # join request
            sock.sendall(json.dumps({"mode":"join","channel":channel,"key":CHANNEL_KEYS[channel].decode(errors="ignore")}).encode())
            print(f"[INFO] Entering {channel} (/exit to leave)")
            while True:
                msg=input()
                if msg=="/exit": break
                iv,ct=aes_encrypt(CHANNEL_KEYS[channel],msg)
                sock.sendall(json.dumps({"mode":"channel","channel":channel,"from":USERNAME,"payload":{"iv":iv.hex(),"ct":ct.hex()}}).encode())
        elif ch=="2":
            to=input("Send to: ")
            while True:
                m=input()
                if m=="/exit": break
                iv,ct=aes_encrypt(CHANNEL_KEYS["channel1"],m)
                sock.sendall(json.dumps({"mode":"direct","from":USERNAME,"to":to,"payload":{"iv":iv.hex(),"ct":ct.hex()}}).encode())
        elif ch=="3":
            to=input("P2P user: ")
            while True:
                m=input()
                if m=="/exit": break
                iv,ct=aes_encrypt(CHANNEL_KEYS["channel1"],m)
                sock.sendall(json.dumps({"mode":"p2p","from":USERNAME,"to":to,"payload":{"iv":iv.hex(),"ct":ct.hex()}}).encode())
        elif ch=="4":
            print("Bye"); sock.close(); sys.exit(0)

def main():
    sock=socket.socket(); sock.connect((HOST,PORT))
    login(sock)
    threading.Thread(target=receive,args=(sock,),daemon=True).start()
    send_messages(sock)

if __name__=="__main__":
    main()
