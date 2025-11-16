"""Append-only transcript + TranscriptHash helpers."""

import hashlib
import os
from pathlib import Path
from cryptography.hazmat.primitives import serialization # <-- ADDED IMPORT

# Ensure the 'transcripts/' directory exists
Path("transcripts").mkdir(exist_ok=True)

class Transcript:
    """
    Manages an append-only log file for a single chat session.
    The format is: seqno | ts | ct | sig | peer-cert-fingerprint
   
    """
    
    def __init__(self, session_id: str):
        self.filename = Path(f"transcripts/{session_id}.txt")
        # 'a' mode = append. Creates the file if it doesn't exist.
        try:
            self.file = open(self.filename, "a", encoding="utf-8")
            print(f"Transcript log opened: {self.filename}")
        except IOError as e:
            print(f"FATAL: Could not open transcript file: {e}")
            raise
    
    def log(
        self,
        seqno: int,
        timestamp: int,
        ciphertext_b64: str,
        signature_b64: str,
        peer_cert_fingerprint: str
    ):
        """
        Appends a single formatted message line to the transcript file.
        """
        # Define the line format
        line = f"{seqno}|{timestamp}|{ciphertext_b64}|{signature_b64}|{peer_cert_fingerprint}\n"
        
        try:
            self.file.write(line)
            # Ensure the line is written to disk immediately
            self.file.flush()
        except IOError as e:
            print(f"Error writing to transcript log: {e}")

    def close(self):
        """Closes the transcript file handle."""
        self.file.close()
        print(f"Transcript log closed: {self.filename}")

    def calculate_hash(self) -> str:
        """
        Reads the entire transcript file and computes its SHA-256 hash.
        This must be called *after* the file is closed to ensure all
        data is read.
       
        """
        if not self.file.closed:
            print("Warning: Calculating hash on a transcript file that is still open.")
            
        try:
            with open(self.filename, "rb") as f:
                file_data = f.read()
            
            # Compute the hash
            transcript_hash = hashlib.sha256(file_data).hexdigest()
            return transcript_hash
            
        except IOError as e:
            print(f"Error reading transcript file for hashing: {e}")
            return ""

def get_cert_fingerprint(cert: 'x509.Certificate') -> str:
    """
    Helper function to get a unique SHA-256 fingerprint for a certificate.
    This is used to identify the peer in the log.
    """
    # --- THIS IS THE FIXED LINE ---
    return hashlib.sha256(cert.public_bytes(encoding=serialization.Encoding.PEM)).hexdigest()