"""Run on the phone side conceptually: generate a random mobile API token and its SHA-256 hash.

The raw token stays on the phone and is used as the Authorization: Bearer value.
Only the hash gets registered on the VPS (see README_VPS.md, "Adding a phone").
"""
import hashlib
import secrets

token = secrets.token_urlsafe(32)
print("Token (enter on the phone, never store it on the VPS):", token)
print("SHA-256 (send this to the VPS admin API instead):", hashlib.sha256(token.encode()).hexdigest())
