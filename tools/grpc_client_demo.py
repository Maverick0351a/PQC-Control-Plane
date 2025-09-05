import argparse
import grpc

from src.signet.grpc import protected_pb2, protected_pb2_grpc  # type: ignore

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
    print('First call (expected un-auth):', resp)


if __name__ == '__main__':  # pragma: no cover
    main()
