import grpc, base64, time, argparse
from src.signet.grpc import protected_pb2, protected_pb2_grpc
from src.signet.crypto.signatures import build_signature_base, sign_ed25519, load_client_keys
from src.signet.crypto.alg_registry import load_private_key
import json

# For demo we reuse caller-1 key if private part available via a helper (not in repo by default)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--host', default='127.0.0.1:50051')
    ap.add_argument('--keyid', default='caller-1')
    ap.add_argument('--private-pem', required=True, help='Path to ed25519 private key pem for caller-1')
    args = ap.parse_args()

    channel = grpc.insecure_channel(args.host)
    stub = protected_pb2_grpc.ProtectedStub(channel)

    # 1. First call without metadata to get challenge
    resp = stub.Call(protected_pb2.ProtectedRequest(message='hi'), metadata=[])
    # Expect failure with challenge header (trailers not standardized here; simplified)
    # For simplicity, server returns ok=False; challenge is not directly accessible in this minimal stub.
    # We simulate by querying receipt store via HTTP in full integration; omitted here.
    print('First call (expected un-auth):', resp)

    # In a production scenario, we'd extract PCH-Challenge from initial metadata; skipping detailed extraction here.

if __name__ == '__main__':
    main()
