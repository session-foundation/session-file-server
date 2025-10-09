from nacl.public import PrivateKey
from nacl.signing import SigningKey
import os

from .web import app

# We support up to *2* possible private keys: one derived from an Ed secret key, the other directly
# from an X private key value.  This is for transition towards deriving everything from an Ed secret
# key, but with existing clients using a known X privkey.
privkeys = []

sk = None

if os.path.exists("key_ed25519"):
    with open("key_ed25519", "rb") as f:
        key = f.read()
        if len(key) == 128 and all(c in '0123456789abcdefABCDEF' for c in key):
            key = bytes.fromhex(key)
        elif (len(key) == 129 and key[-1:] == b"\n") or (len(key) == 130 and key[-2:] == b"\r\n"):
            key = bytes.fromhex(key[0:128].decode())
        elif len(key) != 64:
            raise RuntimeError(f"Invalid key_ed25519: expected 64 bytes or 128 hex, not {len(key)} bytes\n{repr(key)}")

    sk = SigningKey(key[0:32])
    privkeys.append(sk.to_curve25519_private_key())
else:
    sk = SigningKey.generate()
    privkeys.append(sk.to_curve25519_private_key())
    with open("key_ed25519", "wb") as f:
        f.write((sk.encode().hex() + sk.verify_key.encode().hex() + "\n").encode())

app.logger.info(
        f"File server Ed25519 pubkey: {sk.verify_key.encode().hex()}")
app.logger.info(
        f"... which is X25519 pubkey: {sk.to_curve25519_private_key().public_key.encode().hex()}")

if os.path.exists("key_x25519"):
    with open("key_x25519", "rb") as f:
        key = f.read()
        if len(key) != 32:
            raise RuntimeError(
                "Invalid key_x25519: expected 32 bytes, not {} bytes".format(len(key))
            )
    privkeys.append(PrivateKey(key))

    app.logger.info(f"File server X25519-only pubkey: {privkeys[-1].public_key.encode().hex()}")

_server_privkey_bytes = [x.encode() for x in privkeys]
_server_pubkey_bytes = [x.public_key.encode() for x in privkeys]
