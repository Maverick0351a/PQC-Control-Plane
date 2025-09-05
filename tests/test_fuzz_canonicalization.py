import json, hashlib
from hypothesis import given, strategies as st
from starlette.datastructures import Headers
from types import SimpleNamespace

from src.signet.crypto.jcs import jcs_canonicalize
from src.signet.crypto.signatures import build_signature_base

# Strategy for JSON objects without floats (RFC 8785 caveat) and limited depth
json_scalars = st.one_of(
    st.text(max_size=40),
    st.integers(min_value=-10_000, max_value=10_000),
    st.booleans(),
    st.none(),
)

json_arrays = st.lists(json_scalars, max_size=5)
json_objects = st.dictionaries(
    keys=st.text(min_size=1, max_size=10),
    values=st.deferred(lambda: json_scalars | json_arrays),
    max_size=5,
)

json_like = json_objects | json_arrays | json_scalars

@given(json_like)
def test_jcs_stable_deterministic(obj):
    # Two canonicalizations must be identical byte-for-byte
    a = jcs_canonicalize(obj)
    b = jcs_canonicalize(obj)
    assert a == b
    # Re-parse must yield equivalent JSON structure when loaded
    reparsed = json.loads(a.decode())
    # Sort keys for comparison (since jcs sorts already this is strict)
    assert reparsed == json.loads(b.decode())

# Restrict challenge to visible ASCII excluding control and colon characters
challenge_safe = st.text(alphabet=st.characters(min_codepoint=33, max_codepoint=126, blacklist_categories=("Cs",)), min_size=5, max_size=20).filter(lambda s: ':' not in s and '\n' not in s and '\r' not in s)

path_strategy = st.lists(
    st.text(min_size=1, max_size=5).filter(lambda s: '\n' not in s and '\r' not in s),
    min_size=1, max_size=4
).map(lambda segs: "/"+"/".join(segs))

qp_key = st.text(min_size=1, max_size=5).filter(lambda s: '\n' not in s and '\r' not in s)
qp_val = st.text(max_size=5).filter(lambda s: '\n' not in s and '\r' not in s)

@given(
    method=st.sampled_from(["GET","POST","PUT"]),
    path=path_strategy,
    qparams=st.dictionaries(qp_key, qp_val, max_size=3),
    challenge=challenge_safe,
)
def test_signature_base_includes_components(method, path, qparams, challenge):
    # Build fake request minimal interface
    class FakeURL:
        def __init__(self, path, query):
            self.path = path
            self.query = query

    query = "&".join(f"{k}={v}" for k,v in qparams.items())
    headers = Headers({
        "PCH-Challenge": f":{challenge}:",
        "Content-Type": "application/json",
    })
    request = SimpleNamespace(method=method, headers=headers, url=FakeURL(path, query))
    comps = ["@method","@path","pch-challenge","content-type","evidence-sha-256"]
    params = {"created":"1234567890","keyid":"fuzz-client","alg":"ed25519"}
    base = build_signature_base(request, comps, params, evidence_sha256_hex="deadbeef")
    # Assertions: each component appears exactly once as leading token 'name:'
    lines = base.split("\n")
    assert lines[-1].startswith("@signature-params:")
    names = [l.split(":",1)[0] for l in lines[:-1] if ":" in l]
    assert names == [c.lower() for c in comps]
    assert "deadbeef" in base
    # Path formatting check
    # Path value is sanitized (CR/LF removed) in signature base; mirror that for assertion
    sanitized_path = path.replace("\r", "").replace("\n", "")
    if query:
        assert f"{sanitized_path}?{query}" in base
    else:
        assert sanitized_path in base

@given(json_like, json_like)
def test_jcs_order_independence_for_objects(a, b):
    # If converting both into a composite object with swapped key order, canonicalization must be stable
    obj1 = {"x": a, "y": b}
    obj2 = {"y": b, "x": a}
    c1 = jcs_canonicalize(obj1)
    c2 = jcs_canonicalize(obj2)
    assert c1 == c2

