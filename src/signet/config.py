import os
# Header budget guardrails
MAX_HEADER_BYTES = int(os.getenv("MAX_HEADER_BYTES", "16384"))
MAX_SINGLE_HEADER_BYTES = int(os.getenv("MAX_SINGLE_HEADER_BYTES", "8192"))
HEADER_DOWNGRADE_MODE = os.getenv("HEADER_DOWNGRADE_MODE", "hash-only")  # hash-only|body-evidence|deny
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

# Enforcement / guard configuration
ENFORCE_PCH_ROUTES = [p.strip() for p in os.getenv("ENFORCE_PCH_ROUTES", "").split(",") if p.strip()]
REQUIRE_TLS_EXPORTER = os.getenv("REQUIRE_TLS_EXPORTER", "false").lower() == "true"
BREAKER_ENABLED = os.getenv("BREAKER_ENABLED", "false").lower() == "true"
