"""Data model helpers for CBOM export (minimal for now)."""
from dataclasses import dataclass
from typing import List

@dataclass
class AlgorithmDescriptor:
    primitive: str
    name: str
    keySize: int | None = None
    variant: str | None = None
    provider: str | None = None
    provider_version: str | None = None
    fips: bool = False

@dataclass
class KeyDescriptor:
    purpose: str
    type: str
    keySize: int
    lifecycle: str = "active"

@dataclass
class HttpSigDescriptor:
    sig_alg: str
    headers: List[str]
