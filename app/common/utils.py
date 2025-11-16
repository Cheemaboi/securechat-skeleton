"""Helper signatures: now_ms, b64e, b664d, sha256_hex."""

import base64
import time
import hashlib

def now_ms() -> int:
    """Returns the current time in milliseconds."""
    return int(time.time() * 1000)

def b64e(b: bytes) -> str:
    """Base64-encodes bytes into a string."""
    return base64.b64encode(b).decode('ascii')

def b64d(s: str) -> bytes:
    """Base64-decodes a string into bytes."""
    try:
        return base64.b64decode(s)
    except (base64.binascii.Error, TypeError) as e:
        print(f"Error decoding base64 string: {e}")
        # Return a known-bad value or re-raise, depending on required error handling
        return b"" 

def sha256_hex(data: bytes) -> str:
    """Returns the SHA-256 hash of data as a hex string."""
    return hashlib.sha256(data).hexdigest()