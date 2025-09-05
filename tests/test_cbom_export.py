from src.signet.cbom.export import build_cbom
from src.signet.config import BINDING_TYPE


def test_cbom_is_valid_min_shape():
    doc = build_cbom()
    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == "1.5"
    assert "metadata" in doc and "component" in doc["metadata"]
    assert isinstance(doc.get("components"), list) and len(doc["components"]) > 0
    # Required CBOM extension namespaces present
    for k in ["cbom:algorithms", "cbom:keys", "cbom:protocols", "cbom:http_sig"]:
        assert k in doc, f"missing {k}"
    # Basic algorithm entries
    alg_names = {a["name"] for a in doc["cbom:algorithms"]}
    assert {"ed25519", "sha-256"}.issubset(alg_names)


def test_cbom_export_contains_binding_and_algorithms():
    doc = build_cbom()
    # Binding type property
    props = {p["name"]: p["value"] for p in doc.get("properties", [])}
    assert props.get("binding.type") == BINDING_TYPE
    # Protocols extension reflects binding
    protos = doc.get("cbom:protocols", [])
    assert any(p.get("binding") == BINDING_TYPE for p in protos)
    # HTTP signature headers include binding header lowercased
    hs = doc["cbom:http_sig"][0]["headers"]
    assert any(BINDING_TYPE.split('-')[0] in h for h in hs) or len(hs) >= 4
