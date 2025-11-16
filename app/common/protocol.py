"""Pydantic models: hello, server_hello, register, login, dh_client, dh_server, msg, receipt."""

from pydantic import BaseModel, Field
from typing import Literal

# --- 1.1 Control Plane (Negotiation and Authentication) ---

class Hello(BaseModel):
    """
    Client sends its certificate and a nonce.
    [cite: 67]
    """
    type: Literal["hello"] = "hello"
    client_cert: str  # PEM-encoded X.509 certificate
    nonce: str        # Base64-encoded random bytes

class ServerHello(BaseModel):
    """
    Server responds with its certificate and a nonce.
    [cite: 68]
    """
    type: Literal["server_hello"] = "server_hello"
    server_cert: str  # PEM-encoded X.509 certificate
    nonce: str        # Base64-encoded random bytes

class Register(BaseModel):
    """
    Encrypted registration message.
    The spec shows email, username, pwd, salt as top-level fields.
    In a real system, these might be inside a single encrypted 'payload'.
    For simplicity, we can follow the spec format.
    [cite: 69]
    """
    type: Literal["register"] = "register"
    # These fields will be ENCRYPTED before being sent
    email: str
    username: str
    pwd: str          # Base64(sha256(salt||pwd))
    salt: str         # Base64-encoded salt

class Login(BaseModel):
    """
    Encrypted login message.
    [cite: 71]
    """
    type: Literal["login"] = "login"
    # These fields will be ENCRYPTED before being sent
    email: str
    pwd: str          # Base64(sha256(salt||pwd))
    nonce: str        # Base64-encoded nonce

# --- 1.2 Key Agreement (Post-Authentication) ---

class DHClient(BaseModel):
    """
    Client initiates the main DH key exchange.
    [cite: 88-94]
    """
    type: Literal["dh_client"] = "dh_client"
    g: int  # DH parameter g
    p: int  # DH parameter p
    A: int  # Client's public value (g^a mod p)

class DHServer(BaseModel):
    """
    Server responds with its public value.
    [cite: 91-93]
    """
    type: Literal["dh_server"] = "dh_server"
    B: int  # Server's public value (g^b mod p)

# --- 1.3 Data Plane (Encrypted Message Exchange) ---

class Msg(BaseModel):
    """
    A single encrypted and signed chat message.
    [cite: 110-111]
    """
    type: Literal["msg"] = "msg"
    seqno: int  # Sequence number
    ts: int     # Timestamp (Unix milliseconds)
    ct: str     # Base64-encoded ciphertext (AES-128)
    sig: str    # Base64-encoded RSA signature

# --- 1.4 Non-Repudiation (Session Evidence) ---

class Receipt(BaseModel):
    """
    A signed receipt of the entire session transcript.
    [cite: 132-134]
    """
    type: Literal["receipt"] = "receipt"
    peer: Literal["client", "server"]
    first_seq: int
    last_seq: int
    transcript_sha256: str  # Hex-encoded SHA-256 hash
    sig: str                # Base64-encoded RSA signature of the hash