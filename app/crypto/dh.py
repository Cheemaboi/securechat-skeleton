"""Classic DH helpers + Trunc16(SHA256(Ks)) derivation."""

import hashlib
import os
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# We will generate 2048-bit parameters
KEY_SIZE_BITS = 2048

def gen_dh_parameters() -> (int, int, dh.DHPrivateKey):
    """
    Generates new DH parameters (p, g) and a private key.
    This is called by the client.
    """
    # Generate parameters. This can be slow.
    params = dh.generate_parameters(generator=2, key_size=KEY_SIZE_BITS, backend=default_backend())
    p = params.parameter_numbers().p
    g = params.parameter_numbers().g
    
    # Generate a private key using these parameters
    private_key = params.generate_private_key()
    return p, g, private_key

def gen_server_private_key(p: int, g: int) -> dh.DHPrivateKey:
    """
    Generates a DH private key for the server using parameters
    provided by the client.
    """
    try:
        param_nums = dh.DHParameterNumbers(p=p, g=g)
        params = param_nums.parameters(default_backend())
        
        # Generate a private key using these parameters
        private_key = params.generate_private_key()
        return private_key
    except ValueError:
        print("ERROR: Invalid DH parameters received from client.")
        raise

def get_public_value(private_key: dh.DHPrivateKey) -> int:
    """
    Calculates the public value (A or B) from a private key.
    e.g., A = g^a mod p
    """
    public_key = private_key.public_key()
    y = public_key.public_numbers().y
    return y

def get_shared_secret(
    private_key: dh.DHPrivateKey,
    peer_public_value: int
) -> bytes:
    """
    Computes the shared secret Ks given our private key
    and the peer's public value.
    
    Note: The private_key object already contains p and g.
    """
    
    # 1. Reconstruct the peer's public key object
    param_nums = private_key.parameters().parameter_numbers()
    peer_public_numbers = dh.DHPublicNumbers(y=peer_public_value, parameter_numbers=param_nums)
    
    try:
        peer_public_key = peer_public_numbers.public_key(default_backend())
    except ValueError:
        print("Error: Invalid peer public key value (y).")
        raise
        
    # 2. Compute the shared secret (Ks)
    shared_secret_ks = private_key.exchange(peer_public_key)
    
    return shared_secret_ks

def derive_aes_key(shared_secret_ks: bytes) -> bytes:
    """
    Derives the final 16-byte AES key from the raw shared secret (Ks)
    using the formula: K = Trunc16(SHA256(big-endian(Ks)))
    """
    hash_bytes = hashlib.sha256(shared_secret_ks).digest()
    aes_key = hash_bytes[:16]
    return aes_key