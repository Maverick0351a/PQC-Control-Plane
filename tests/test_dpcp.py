"""DPCP placeholder tests (skipped)."""
import pytest
try:
    import ed25519  # type: ignore
except Exception:  # pragma: no cover - library optional for now
    ed25519 = None

# Placeholder tests for DPCP; real implementation pending wiring of DPR emission inside app.

@pytest.mark.skip(reason="DPCP integration not yet wired into FastAPI app")
def test_dpcp_receipt_sign_and_verify():
    if ed25519:
        sk, vk = ed25519.create_keypair()
        msg = b'{"v":1,"ts":1,"method":"GET","path":"/x","cb":"AAA=","req_sha384":"dead","rsp_sha384":"beef"}'
        sig = sk.sign(msg)
        vk.verify(sig, msg)

@pytest.mark.skip(reason="stream truncation flag not implemented")
def test_dpcp_streaming_large_body_truncation_flag():
    pass

@pytest.mark.skip(reason="0-RTT upgrade logic not implemented")
def test_dpcp_0rtt_unavailable_then_upgrade():
    pass

@pytest.mark.skip(reason="join + FVaR integration requires running receipt sink")
def test_dpcp_join_with_pqc_receipts_fvar():
    pass
