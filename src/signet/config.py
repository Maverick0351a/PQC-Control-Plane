import os
from dotenv import load_dotenv
load_dotenv()

FEATURE_PCH = os.getenv("FEATURE_PCH", "true").lower() == "true"
PCH_ADVISORY = os.getenv("PCH_ADVISORY", "true").lower() == "true"
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
DATA_DIR = os.getenv("DATA_DIR", "var/data")
SERVER_SIGNING_KEY = os.getenv("SERVER_SIGNING_KEY", "keys/sth_ed25519_sk.pem")
CLIENT_KEYS = os.getenv("CLIENT_KEYS", "config/clients.json")
BINDING_HEADER = os.getenv("BINDING_HEADER", "X-TLS-Session-ID")  # MVP; later: exporter
BINDING_TYPE = os.getenv("BINDING_TYPE", "tls-session-id")        # later: tls-exporter
