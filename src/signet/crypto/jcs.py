# Minimal JCS-like canonicalization for strings/ints/bools/objects/arrays without floats.
# NOTE: For full RFC 8785 compliance (numbers), avoid floats in signed payloads.
import json

def jcs_canonicalize(obj) -> bytes:
    def sort_obj(o):
        if isinstance(o, dict):
            return {k: sort_obj(o[k]) for k in sorted(o.keys())}
        elif isinstance(o, list):
            return [sort_obj(i) for i in o]
        else:
            return o
    sorted_obj = sort_obj(obj)
    # separators removes spaces; ensure_ascii=False to preserve UTF-8; sort_keys handled above
    text = json.dumps(sorted_obj, separators=(',', ':'), ensure_ascii=False)
    return text.encode("utf-8")
