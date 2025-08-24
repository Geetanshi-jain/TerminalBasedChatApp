
## Introduction :

Terminal-Based Chat Application with Encryption (Networking)

Problem Statement:
Build a secure terminal-based chat application for multiple users. The chat should happen in real-time over a network, and all messages must be encrypted. You can use a standard library such as OpenSSL (or any cryptographic library) for the encryption functions.






## Key constraints
1.Support at least two concurrent users with real-time messaging.

2.Implement end-to-end encryption using a symmetric key algorithm (e.g., AES). For simplicity, the key can be pre-shared (hardcoded) in both client and server.

3.Include basic username/password authentication at the start.

4.Use colored text in the terminal to improve readability.
## Solution :
Create a secure terminal-based chat application that supports encrypted messaging between clients using pre-shared symmetric keys. Only authenticated users should be allowed to participate, and messages should be encrypted end-to-end using AES. The server should act as a relay, forwarding encrypted messages between clients without having access to the plaintext. The login credentials should also be encrypted using a separate symmetric key to ensure secure authentication.

## Design 

## High Level Design : 
## <img src="diagram.png" alt="Workflow Diagram" width="400" height="300"/>

---

## Approach

### 🧑‍💻 Clients
- Each client has:
  - A **hardcoded symmetric AES key** (for encrypting/decrypting messages between clients).
  - A **unique symmetric key** shared with the server (used **only for login authentication**).

### 🖥️ Server
- Stores all clients' **username:password** pairs.
- These credentials are encrypted using the **login symmetric key** (shared only with that client).
- Responsible for:
  - Decrypting login credentials.
  - Verifying authentication.
  - Managing client threads for communication.
  - Redirecting (not decrypting) client messages.

---

## 🔐 Login Process
1. Client → Server: Sends `username:password` encrypted with its **login symmetric key**.
2. Server → Decrypts & verifies credentials.
3. On success → Server spawns a **thread** for client communication.

---

## 💬 Messaging Process
1. **Client A** encrypts the message using the **client-to-client AES key**.
2. Server forwards the encrypted message (without decryption).
3. **Client B** decrypts it using the same AES key.
4. ✅ Only the intended client can read the message.

---

## Implementation

## 🛠️ Implementation -  Tech Stack

**Programming Language:**  
- Python 3.x  

**Core Libraries & Modules:**  
- `socket` → For client-server communication  
- `threading` → For handling multiple client connections concurrently  
- `cryptography` (`Fernet` / AES) → For encryption and decryption of messages  


**Encryption:**  
- AES (Advanced Encryption Standard) for secure message exchange between clients  
- Symmetric Key Encryption for client-server login authentication  

**Server-Side:**  
- Python socket server managing multiple client connections using threads  
- Stores encrypted username-password credentials  
- Redirects encrypted messages without decryption  

**Client-Side:**  
- Hardcoded symmetric AES key for end-to-end encryption  
- Symmetric login key (client ↔ server authentication)  
- Handles encryption before sending and decryption after receiving  

## 🧪 Testing

### Unit Testing Coverage
- **AES Encryption/Decryption** → Verify correctness & payload integrity.  
- **Login Authentication** → Check valid/invalid credentials securely.  
- **Message Forwarding** → Ensure encrypted forwarding across multi-threaded clients.  
- **Error Handling** → Handle disconnects, invalid keys, and corrupted data gracefully.  

## Deployment
The code is deployed on GitHub, and you can check out the application through this [link](https://github.com/your-username/your-repo-name).

## External Features 
1. Chat Channel (Group Chat) – Allows multiple users to communicate together in a shared channel, sending and receiving messages in real-time.


## 🚀 Application Running Steps (Compact)

1. **Clone Repo:** `git clone https://github.com/your-username/your-repo-name.git && cd your-repo-name`  
2. **Install Packages:** `pip install -r requirements.txt`  
3. **Run Server:** `python server.py` (starts listening for clients)  
4. **Run Clients:** `python client.py` (open multiple terminals, enter username & password)  
5. **Start Chatting:** Choose Channel Chat / Direct Message / Point-to-Point Chat; messages are AES encrypted.  
6. **Exit:** Type `/exit` in client or close terminal.  

