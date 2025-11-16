"""Server skeleton — plain TCP; no TLS. See assignment spec."""

import socket
import threading
import json
import hashlib
import os
from cryptography import x509

# Import all your helper modules
from app.common import protocol
from app.common.utils import b64e, b64d, now_ms, sha256_hex
from app.crypto import aes, dh, pki, sign
from app.storage import db, transcript

# --- Server Configuration ---
HOST = '0.0.0.0'  # Listen on all available interfaces
PORT = 6000

# --- ADD THIS CLASS ---
class SecurityError(Exception):
    """Custom exception for protocol security failures."""
    pass


# --- Server Configuration ---
HOST = '0.0.0.0'  # Listen on all available interfaces
PORT = 6000
SERVER_CN = "server.local"
CLIENT_CN = "client.local"

# --- Load Server Credentials ---
try:
    print("Loading server credentials...")
    CA_CERT_PATH = "certs/ca_cert.pem"
    SERVER_CERT_PATH = "certs/server_cert.pem"
    SERVER_KEY_PATH = "certs/server_key.pem"

    CA_CERT = pki.load_ca_cert(CA_CERT_PATH)
    SERVER_PRIV_KEY = sign.load_private_key(SERVER_KEY_PATH)
    
    with open(SERVER_CERT_PATH, "r") as f:
        SERVER_CERT_PEM = f.read()
    
    SERVER_CERT = pki.load_cert_from_str(SERVER_CERT_PEM)
    SERVER_CERT_FINGERPRINT = transcript.get_cert_fingerprint(SERVER_CERT)
    print("Server credentials loaded successfully.")
except FileNotFoundError:
    print("Error: Certificate files not found. Did you run the 'scripts/' first?")
    exit(1)


def handle_client(conn: socket.socket, addr):
    print(f"[+] New connection from {addr}")
    
    client_cert = None
    client_cert_fingerprint = "UNKNOWN"
    session_key = None
    session_id = f"{addr[0]}_{addr[1]}_{now_ms()}"
    server_seqno = 0
    client_seqno = 0
    
    try:
        session_transcript = transcript.Transcript(session_id)
    except Exception as e:
        print(f"[-] Failed to create transcript for {addr}: {e}")
        conn.close()
        return

    try:
        # --- 1. PKI & Certificate Exchange ---
        print(f"[{addr}] Starting PKI exchange...")
        hello_data = conn.recv(4096)
        if not hello_data: raise ConnectionError("Client disconnected during hello")
        
        client_hello = protocol.Hello.model_validate_json(hello_data)
        client_cert = pki.load_cert_from_str(client_hello.client_cert)
        
        if not pki.verify_certificate(client_cert, CA_CERT, expected_cn=CLIENT_CN):
            raise SecurityError("Client certificate validation failed")
            
        client_cert_fingerprint = transcript.get_cert_fingerprint(client_cert)
        print(f"[{addr}] Client certificate verified.")
        
        server_hello = protocol.ServerHello(server_cert=SERVER_CERT_PEM, nonce=b64e(os.urandom(16)))
        conn.sendall(server_hello.model_dump_json().encode())

        # --- 2. Auth (Control Plane) ---
        print(f"[{addr}] Starting temporary DH for auth...")
        
        # 2a. Receive DHClient message (with p and g)
        dh_client_data = conn.recv(4096)
        dh_client_msg = protocol.DHClient.model_validate_json(dh_client_data)
        
        # 2b. Generate Server DH keys using client's p and g
        temp_b = dh.gen_server_private_key(p=dh_client_msg.p, g=dh_client_msg.g)
        temp_B_val = dh.get_public_value(temp_b)
        
        # Send DHServer message
        dh_server_msg = protocol.DHServer(B=temp_B_val)
        conn.sendall(dh_server_msg.model_dump_json().encode())
        
        # 2c. Derive Temporary AES Key
        temp_ks = dh.get_shared_secret(temp_b, dh_client_msg.A)
        temp_aes_key = dh.derive_aes_key(temp_ks)
        print(f"[{addr}] Temporary AES key derived.")

        # 2d. Receive and Decrypt Auth Message
        encrypted_auth_data = conn.recv(4096)
        auth_json = aes.decrypt(temp_aes_key, encrypted_auth_data)
        auth_msg = json.loads(auth_json)
        
        auth_ok = False
        if auth_msg.get("type") == "register":
            print(f"[{addr}] Processing registration for {auth_msg['email']}")
            reg_msg = protocol.Register.model_validate(auth_msg)
            # As per spec, client generates salt and hash. We store them.
            try:
                db.register_user(
                    reg_msg.email,
                    reg_msg.username,
                    b64d(reg_msg.salt),
                    b64d(reg_msg.pwd).hex() # Store hash as hex
                )
                auth_ok = True
            except Exception as e:
                print(f"[{addr}] DB Error during register: {e}")
                auth_ok = False

        elif auth_msg.get("type") == "login":
            print(f"[{addr}] Processing login for {auth_msg['email']}")
            login_msg = protocol.Login.model_validate(auth_msg)
            user_data = db.get_user_for_login(login_msg.email)
            
            if user_data:
                # Re-compute hash using client's *plaintext* pwd and stored salt
                client_pwd_hash = hashlib.sha256(user_data['salt'] + login_msg.pwd.encode()).hexdigest()
                
                if client_pwd_hash == user_data['pwd_hash']:
                    print(f"[{addr}] Login successful for {login_msg.email}")
                    auth_ok = True
                else:
                    print(f"[{addr}] Login FAILED: Password mismatch.")
            else:
                print(f"[{addr}] Login FAILED: No such user.")
        
        # 2e. Send Auth Response (encrypted)
        auth_response = {"status": "ok" if auth_ok else "fail"}
        encrypted_response = aes.encrypt(temp_aes_key, json.dumps(auth_response).encode())
        conn.sendall(encrypted_response)
        
        if not auth_ok: raise SecurityError("Authentication failed")

        # --- 3. Session Key Establishment (Main) ---
        print(f"[{addr}] Starting MAIN DH for session key...")
        
        # 3a. Receive DHClient message (with p and g)
        dh_client_data = conn.recv(4096)
        dh_client_msg = protocol.DHClient.model_validate_json(dh_client_data)
        
        # 3b. Generate Server DH keys using client's p and g
        main_b = dh.gen_server_private_key(p=dh_client_msg.p, g=dh_client_msg.g)
        main_B_val = dh.get_public_value(main_b)
        
        dh_server_msg = protocol.DHServer(B=main_B_val)
        conn.sendall(dh_server_msg.model_dump_json().encode())
        
        # 3c. Derive Main Session Key
        main_ks = dh.get_shared_secret(main_b, dh_client_msg.A)
        session_key = dh.derive_aes_key(main_ks)
        print(f"[{addr}] MAIN session key derived. Chat is now SECURE.")

        # --- 4. Encrypted Chat (Data Plane) ---
        while True:
            msg_data = conn.recv(4096)
            if not msg_data: break # Client closed connection
            
            msg = protocol.Msg.model_validate_json(msg_data)
            
            if msg.seqno <= client_seqno:
                print(f"[{addr}] REPLAY DETECTED. Got {msg.seqno}, expected > {client_seqno}")
                continue
            client_seqno = msg.seqno
            
            hash_data = f"{msg.seqno}{msg.ts}{msg.ct}".encode()
            h = hashlib.sha256(hash_data).digest()
            
            client_pub_key = client_cert.public_key()
            if not sign.verify(client_pub_key, h, b64d(msg.sig)):
                print(f"[{addr}] SIGNATURE FAILED. Message tampered.")
                continue
            
            session_transcript.log(msg.seqno, msg.ts, msg.ct, msg.sig, client_cert_fingerprint)
            
            plaintext = aes.decrypt(session_key, b64d(msg.ct))
            print(f"[CHAT from {addr}]: {plaintext.decode()}")

            # --- Echo message back ---
            server_seqno += 1
            echo_ts = now_ms()
            echo_ct = b64e(aes.encrypt(session_key, f"Server received: {plaintext.decode()}".encode()))
            
            echo_hash_data = f"{server_seqno}{echo_ts}{echo_ct}".encode()
            echo_h = hashlib.sha256(echo_hash_data).digest()
            echo_sig = b64e(sign.sign(SERVER_PRIV_KEY, echo_h))
            
            echo_msg = protocol.Msg(seqno=server_seqno, ts=echo_ts, ct=echo_ct, sig=echo_sig)
            conn.sendall(echo_msg.model_dump_json().encode())
            
            session_transcript.log(server_seqno, echo_ts, echo_ct, echo_sig, SERVER_CERT_FINGERPRINT)

    except (ConnectionError, ConnectionResetError) as e:
        print(f"[-] Client {addr} disconnected: {e}")
    except SecurityError as e:
        print(f"[-] Security error with {addr}: {e}. Closing connection.")
    except Exception as e:
        print(f"[-] An unexpected error occurred with {addr}: {e}")
    
    finally:
        # --- 5. Teardown & Non-Repudiation ---
        print(f"[{addr}] Closing connection.")
        session_transcript.close()
        
        final_hash = session_transcript.calculate_hash()
        hash_sig = b64e(sign.sign(SERVER_PRIV_KEY, final_hash.encode()))
        
        receipt = protocol.Receipt(
            peer="server", first_seq=1, last_seq=server_seqno,
            transcript_sha256=final_hash, sig=hash_sig
        )
        try:
            conn.sendall(receipt.model_dump_json().encode())
        except:
            pass # Client might already be gone
            
        conn.close()


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((HOST, PORT))
    sock.listen()
    print(f"[*] Server listening on {HOST}:{PORT}...")

    while True:
        conn, addr = sock.accept()
        client_thread = threading.Thread(target=handle_client, args=(conn, addr))
        client_thread.daemon = True
        client_thread.start()

if __name__ == "__main__":
    # --- This patch updates the db functions ---
    # This is to match the spec where client sends hash on register
    # but plaintext on login.
    
    def register_user_fixed(email, username, salt_bytes, pwd_hash_hex):
        """Stores the user with pre-hashed password."""
        conn = db.get_db_connection()
        try:
            with conn.cursor() as cursor:
                sql = "INSERT INTO users (email, username, salt, pwd_hash) VALUES (%s, %s, %s, %s)"
                cursor.execute(sql, (email, username, salt_bytes, pwd_hash_hex))
            conn.commit()
            print(f"Successfully registered user: {username}")
            return True
        except db.pymysql.MySQLError as e:
            print(f"Error registering user: {e}")
            return False
        finally:
            conn.close()

    def get_user_for_login_fixed(email):
        """Fetches user data, including salt."""
        conn = db.get_db_connection()
        try:
            with conn.cursor() as cursor:
                sql = "SELECT salt, pwd_hash FROM users WHERE email = %s"
                cursor.execute(sql, (email,))
                result = cursor.fetchone() # result is a dict
                return result
        except db.pymysql.MySQLError as e:
            print(f"Error fetching user: {e}")
            return None
        finally:
            conn.close()

    # Monkey-patch the db functions
    db.register_user = register_user_fixed
    db.get_user_for_login = get_user_for_login_fixed

    main()