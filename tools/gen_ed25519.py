from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
import base64
import json
import os

os.makedirs("keys", exist_ok=True)
os.makedirs("config", exist_ok=True)

# Server STH key
sk = Ed25519PrivateKey.generate()
with open("keys/sth_ed25519_sk.pem", "wb") as f:
    f.write(sk.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))
with open("keys/sth_ed25519_pk.pem", "wb") as f:
    f.write(sk.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

# Client demo key
ck = Ed25519PrivateKey.generate()
client_priv_pem = ck.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
).decode()
client_pub_raw = ck.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
)
client_pub_b64 = base64.b64encode(client_pub_raw).decode()

with open("keys/client_demo_sk.pem", "w") as f:
    f.write(client_priv_pem)

clients = {
    "caller-1": {
        "alg": "ed25519",
        "public_key_b64": client_pub_b64
    }
}
with open("config/clients.json", "w") as f:
    json.dump(clients, f, indent=2)

print("Generated: keys/sth_ed25519_sk.pem, keys/sth_ed25519_pk.pem, keys/client_demo_sk.pem, config/clients.json")
