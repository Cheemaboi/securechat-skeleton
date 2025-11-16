"""Client skeleton — plain TCP; no TLS. See assignment spec."""

import socket
import threading
import json
import hashlib
import os
import getpass # For typing passwords
from cryptography import x509

# Import all your helper modules
from app.common import protocol
from app.common.utils import b64e, b64d, now_ms, sha256_hex
from app.crypto import aes, dh, pki, sign
from app.storage import transcript

# --- Client Configuration ---
SERVER_HOST = '127.0.0.1' # Connect to localhost
SERVER_PORT = 6000

# --- ADD THIS CLASS ---
class SecurityError(Exception):
    """Custom exception for protocol security failures."""
    pass
# --- END OF ADDITION ---

# --- Client Configuration ---
SERVER_HOST = '127.0.0.1' # Connect to localhost
SERVER_PORT = 6000
CLIENT_CN = "client.local"
SERVER_CN = "server.local"

# --- Global State ---
session_key = None
session_transcript = None
client_seqno = 0
server_seqno = 0
exit_event = threading.Event() # Used to signal the receiver thread to stop

# --- Load Client Credentials ---
try:
    print("Loading client credentials...")
    CA_CERT_PATH = "certs/ca_cert.pem"
    CLIENT_CERT_PATH = "certs/client_cert.pem"
    CLIENT_KEY_PATH = "certs/client_key.pem"
    SERVER_CERT_PATH = "certs/server_cert.pem" # To get server public key

    CA_CERT = pki.load_ca_cert(CA_CERT_PATH)
    CLIENT_PRIV_KEY = sign.load_private_key(CLIENT_KEY_PATH)
    
    with open(CLIENT_CERT_PATH, "r") as f:
        CLIENT_CERT_PEM = f.read()
    
    CLIENT_CERT = pki.load_cert_from_str(CLIENT_CERT_PEM)
    CLIENT_CERT_FINGERPRINT = transcript.get_cert_fingerprint(CLIENT_CERT)

    SERVER_PUB_KEY = sign.load_public_key_from_cert(SERVER_CERT_PATH)
    SERVER_CERT = pki.load_ca_cert(SERVER_CERT_PATH)
    SERVER_CERT_FINGERPRINT = transcript.get_cert_fingerprint(SERVER_CERT)
    print("Client credentials loaded successfully.")
except FileNotFoundError:
    print("Error: Certificate files not found. Did you run the 'scripts/' first?")
    exit(1)


def receive_thread(conn: socket.socket):
    global server_seqno
    print("Receiver thread started. Waiting for messages...")
    try:
        while not exit_event.is_set():
            data = conn.recv(4096)
            if not data:
                print("\n[!] Server disconnected.")
                exit_event.set()
                break
                
            msg_data = data.decode()
            
            try:
                msg_json = json.loads(msg_data)
            except json.JSONDecodeError:
                print(f"\n[!] Received invalid JSON: {msg_data}")
                continue

            if msg_json.get("type") == "receipt":
                print("\n[!] Received final session receipt from server.")
                receipt = protocol.Receipt.model_validate(msg_json)
                
                receipt_hash = receipt.transcript_sha256
                if sign.verify(SERVER_PUB_KEY, receipt_hash.encode(), b64d(receipt.sig)):
                    print("[!] Server receipt signature is VALID.")
                else:
                    print("[!] WARNING: Server receipt signature is INVALID.")
                continue

            msg = protocol.Msg.model_validate_json(msg_data)
            
            if msg.seqno <= server_seqno:
                print(f"\n[!] REPLAY DETECTED from server. Got {msg.seqno}, expected > {server_seqno}")
                continue
            server_seqno = msg.seqno
            
            hash_data = f"{msg.seqno}{msg.ts}{msg.ct}".encode()
            h = hashlib.sha256(hash_data).digest()
            
            if not sign.verify(SERVER_PUB_KEY, h, b64d(msg.sig)):
                print(f"\n[!] SERVER SIGNATURE FAILED. Message tampered.")
                continue
            
            session_transcript.log(msg.seqno, msg.ts, msg.ct, msg.sig, SERVER_CERT_FINGERPRINT)
            
            plaintext = aes.decrypt(session_key, b64d(msg.ct))
            print(f"\n[Server]: {plaintext.decode()}")
            
    except (ConnectionError, ConnectionResetError):
        if not exit_event.is_set(): print("\n[!] Connection to server lost.")
    except Exception as e:
        if not exit_event.is_set(): print(f"\n[!] Error in receiver thread: {e}")
    
    print("Receiver thread stopping.")

def main():
    global session_key, session_transcript, client_seqno
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        # --- 0. Connect ---
        print(f"Connecting to {SERVER_HOST}:{SERVER_PORT}...")
        sock.connect((SERVER_HOST, SERVER_PORT))
        print("Connected!")
        session_id = f"{SERVER_HOST}_{SERVER_PORT}_{now_ms()}"

        # --- 1. PKI & Certificate Exchange ---
        print("Starting PKI exchange...")
        
        client_hello = protocol.Hello(client_cert=CLIENT_CERT_PEM, nonce=b64e(os.urandom(16)))
        sock.sendall(client_hello.model_dump_json().encode())
        
        server_hello_data = sock.recv(4096)
        if not server_hello_data:
            raise ConnectionError("Server disconnected during hello")
            
        server_hello = protocol.ServerHello.model_validate_json(server_hello_data)
        
        server_cert = pki.load_cert_from_str(server_hello.server_cert)
        if not pki.verify_certificate(server_cert, CA_CERT, expected_cn=SERVER_CN):
            raise SecurityError("Server certificate validation failed! Closing.")
            
        print("Server certificate verified.")

        # --- 2. Auth (Control Plane) ---
        print("Starting temporary DH for auth... (may take a moment to generate p,g)")
        
        # 2a. Generate Client DH keys (and p, g)
        p, g, temp_a = dh.gen_dh_parameters()
        temp_A_val = dh.get_public_value(temp_a)
        
        # Send DHClient message (with p and g)
        dh_client_msg = protocol.DHClient(g=g, p=p, A=temp_A_val)
        sock.sendall(dh_client_msg.model_dump_json().encode())
        
        # 2b. Receive Server DH value
        dh_server_data = sock.recv(4096)
        dh_server_msg = protocol.DHServer.model_validate_json(dh_server_data)
        
        # 2c. Derive Temporary AES Key
        temp_ks = dh.get_shared_secret(temp_a, dh_server_msg.B)
        temp_aes_key = dh.derive_aes_key(temp_ks)
        print("Temporary AES key derived.")

        # 2d. Get User Credentials
        auth_type = ""
        while auth_type not in ["login", "register"]:
            auth_type = input("Do you want to (login) or (register)? ").strip().lower()
            
        email = input("Email: ")
        password = getpass.getpass("Password: ")
        
        auth_payload = {}
        if auth_type == "register":
            username = input("Username: ")
            # As per spec, client generates salt and hashes
            salt = os.urandom(16)
            pwd_hash = hashlib.sha256(salt + password.encode()).digest()
            
            auth_payload = protocol.Register(
                email=email, username=username,
                pwd=b64e(pwd_hash), salt=b64e(salt)
            ).model_dump()
            
        else: # login
            # As per spec, client sends plaintext password (encrypted)
            auth_payload = protocol.Login(
                email=email, pwd=password,
                nonce=b64e(os.urandom(16))
            ).model_dump()

        # 2e. Send Encrypted Auth Message
        encrypted_payload = aes.encrypt(temp_aes_key, json.dumps(auth_payload).encode())
        sock.sendall(encrypted_payload)
        
        # 2f. Receive Auth Response
        encrypted_response = sock.recv(4096)
        response_json = aes.decrypt(temp_aes_key, encrypted_response)
        response = json.loads(response_json)
        
        if response.get("status") != "ok":
            raise SecurityError("Authentication failed. Server rejected login/register.")
            
        print(f"Successfully {auth_type} as {email}!")

        # --- 3. Session Key Establishment (Main) ---
        print("Starting MAIN DH for session key... (may take a moment)")
        
        # 3a. Generate Client DH keys (and p, g)
        p_main, g_main, main_a = dh.gen_dh_parameters()
        main_A_val = dh.get_public_value(main_a)
        
        dh_client_msg = protocol.DHClient(g=g_main, p=p_main, A=main_A_val)
        sock.sendall(dh_client_msg.model_dump_json().encode())
        
        # 3b. Receive Server DH value
        dh_server_data = sock.recv(4096)
        dh_server_msg = protocol.DHServer.model_validate_json(dh_server_data)
        
        # 3c. Derive Main Session Key
        main_ks = dh.get_shared_secret(main_a, dh_server_msg.B)
        session_key = dh.derive_aes_key(main_ks)
        print("MAIN session key derived. Chat is now SECURE.")
        print("Type /exit to quit.")

        # --- 4. Encrypted Chat (Data Plane) ---
        session_transcript = transcript.Transcript(session_id)
        
        receiver = threading.Thread(target=receive_thread, args=(sock,))
        receiver.daemon = True
        receiver.start()
        
        while True:
            msg_text = input("[You]: ")
            
            if msg_text == "/exit":
                exit_event.set()
                break
                
            ct_bytes = aes.encrypt(session_key, msg_text.encode())
            ct_b64 = b64e(ct_bytes)
            
            client_seqno += 1
            ts = now_ms()
            hash_data = f"{client_seqno}{ts}{ct_b64}".encode()
            h = hashlib.sha256(hash_data).digest()
            sig_b64 = b64e(sign.sign(CLIENT_PRIV_KEY, h))
            
            session_transcript.log(client_seqno, ts, ct_b64, sig_b64, CLIENT_CERT_FINGERPRINT)
            
            msg = protocol.Msg(seqno=client_seqno, ts=ts, ct=ct_b64, sig=sig_b64)
            sock.sendall(msg.model_dump_json().encode())
            
    except (ConnectionError, ConnectionResetError) as e:
        print(f"\n[!] Connection error: {e}")
    except SecurityError as e:
        print(f"\n[!] Security error: {e}")
    except Exception as e:
        print(f"\n[!] An unexpected error occurred: {e}")
        
    finally:
        # --- 5. Teardown & Non-Repudiation ---
        print("\nSending final receipt...")
        exit_event.set()
        
        if session_transcript:
            session_transcript.close()
            final_hash = session_transcript.calculate_hash()
            hash_sig = b64e(sign.sign(CLIENT_PRIV_KEY, final_hash.encode()))
            
            receipt = protocol.Receipt(
                peer="client", first_seq=1, last_seq=client_seqno,
                transcript_sha256=final_hash, sig=hash_sig
            )
            try:
                sock.sendall(receipt.model_dump_json().encode())
            except:
                pass
            
        if 'receiver' in locals() and receiver.is_alive():
            receiver.join()
            
        sock.close()
        print("Connection closed. Goodbye.")

if __name__ == "__main__":
    main()