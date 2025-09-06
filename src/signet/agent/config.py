from pydantic import BaseModel
import os


class AgentConfig(BaseModel):
    enabled: bool = os.getenv("AGENT_ENABLED", "true").lower() == "true"
    advisory: bool = os.getenv("AGENT_ADVISORY", "true").lower() == "true"
    require_evidence: bool = os.getenv("AGENT_REQUIRE_EVIDENCE", "true").lower() == "true"

    vdc_sign_key: str = os.getenv("VDC_SIGN_KEY", "keys/agent_ed25519_sk.pem")
    vdc_verify_dir: str = os.getenv("VDC_VERIFY_KEYS_DIR", "keys/trust")
    vdc_hash_alg: str = os.getenv("VDC_HASH_ALG", "sha384")

    evg_enabled: bool = os.getenv("SIGNET_EVG_ENABLED", "true").lower() == "true"
    evg_sink_url: str = os.getenv("RECEIPTS_SINK_URL", "http://evg:8088/ingest")
    sndt_url: str = os.getenv("SNDT_URL", "http://sndt:8090")
    opa_url: str = os.getenv("OPA_URL", "http://opa:8181")

    pathlab_url: str = os.getenv("PATHLAB_URL", "http://pathlab:13000")
    pqcoaster_url: str = os.getenv("PQCOASTER_URL", "http://pqcoaster:14000")

    prom_ns: str = os.getenv("PROM_NAMESPACE", "signet_agent")

    github_token: str | None = os.getenv("GITHUB_TOKEN")
    github_repo: str | None = os.getenv("GITHUB_REPO")


CFG = AgentConfig()


# Back-compat with existing imports
def load_agent_config() -> AgentConfig:  # pragma: no cover - shim
    return CFG
