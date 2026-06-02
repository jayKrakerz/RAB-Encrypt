#!/usr/bin/env python3
"""
One-time setup: encrypts a PDF with Fernet (AES-128-CBC + HMAC) and prints the key.

Usage:
    python setup_encrypt.py path/to/document.pdf

Output: document.pdf.enc in the current directory + the FERNET_KEY to store
in your environment. Delete the original PDF once you have verified the
encrypted file works.
"""
import sys
from pathlib import Path
from cryptography.fernet import Fernet


def main() -> None:
    if len(sys.argv) != 2:
        print("Usage: python setup_encrypt.py <path_to_pdf>")
        sys.exit(1)

    src = Path(sys.argv[1])
    if not src.is_file():
        print(f"Error: {src} not found")
        sys.exit(1)

    key = Fernet.generate_key()
    fernet = Fernet(key)

    ciphertext = fernet.encrypt(src.read_bytes())

    out = Path("document.pdf.enc")
    out.write_bytes(ciphertext)

    print(f"[ok] Encrypted PDF written to: {out}")
    print()
    print("Add this to your environment (never commit it):")
    print(f"  FERNET_KEY={key.decode()}")
    print()
    print("Once confirmed, delete the original PDF from disk.")


if __name__ == "__main__":
    main()
