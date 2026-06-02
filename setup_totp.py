#!/usr/bin/env python3
"""
One-time TOTP setup: generates a secret for admin 2FA.
Run once and add the output to your .env as ADMIN_TOTP_SECRET=<secret>
"""
import pyotp

secret = pyotp.random_base32()
totp = pyotp.TOTP(secret)
uri = totp.provisioning_uri(name="admin", issuer_name="SecureDocs")

print(f"ADMIN_TOTP_SECRET={secret}")
print()
print("Scan this URI with your authenticator app (Google Authenticator, Authy, etc.):")
print(f"  {uri}")
print()
print("Or generate a QR code from this URI at: https://qr.io")
print()
print("Add ADMIN_TOTP_SECRET to your .env then restart the server.")
