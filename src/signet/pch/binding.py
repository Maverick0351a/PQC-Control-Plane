import base64
from typing import Tuple
from ..config import BINDING_TYPE, BINDING_HEADER

# Abstraction for channel binding extraction

def extract_binding(headers_lower) -> Tuple[str, str]:
    """Return (binding_type, binding_id_or_empty).

    Preference order:
      1. If an exporter header is present, treat as tls-exporter regardless of global config.
      2. Else if global BINDING_TYPE demands exporter, return exporter (possibly empty) to signal requirement.
      3. Else fall back to session-id header.
    """
    exporter_hdr = headers_lower.get('x-tls-exporter')
    if exporter_hdr:
        try:
            _ = base64.b64decode(exporter_hdr)
            return ('tls-exporter', exporter_hdr)
        except Exception:
            return ('tls-exporter', '')
    if BINDING_TYPE == 'tls-exporter':  # configured but header missing
        return ('tls-exporter', '')
    sid = headers_lower.get(BINDING_HEADER.lower(), '')
    return ('tls-session-id', sid)
