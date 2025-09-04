# PQC Control Plane

Signet PQC Control Plane MVP with PCH-Lite (Proof-of-Challenge Handshake) middleware, enforcement receipts, Merkle transparency, and compliance pack generation.

## Key Features
- FastAPI service with /protected endpoint guarded by PCH-Lite challenge/response
- Receipt emission (Merkle-tree anchored) for each enforcement decision
- Compliance pack builder with offline inclusion verification
- Demo PCH client for local testing

## Quick Start
```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m uvicorn src.signet.app:app --port 8080
```

## PCH Round Trip
```powershell
powershell -ExecutionPolicy Bypass -File scripts/e2e_pch.ps1
```

## Compliance Pack
```powershell
powershell -ExecutionPolicy Bypass -File scripts/build_compliance_pack.ps1
```

## Tests
```powershell
.venv\Scripts\python -m pytest -q
```

MIT License.