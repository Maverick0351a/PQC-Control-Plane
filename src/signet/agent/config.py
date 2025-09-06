from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass
class AgentConfig:
    advisory: bool = True
    enable_sentinel: bool = True
    enable_weekly_pentest: bool = True
    evg_enabled: bool = os.getenv("SIGNET_EVG_ENABLED", "true").lower() == "true"
    sndt_enabled: bool = os.getenv("SNDT_ENABLED", "false").lower() == "true"
    opa_url: str | None = os.getenv("OPA_URL")
    github_token: str | None = os.getenv("GITHUB_TOKEN")
    producer: str = os.getenv("VDC_PRODUCER_DID", os.getenv("SIGNET_SERVICE", "signet-agent"))


def load_agent_config() -> AgentConfig:
    return AgentConfig()
