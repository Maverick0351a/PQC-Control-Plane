import grpc, asyncio, base64, time
from concurrent import futures
from . import protected_pb2, protected_pb2_grpc
from ..crypto.signatures import parse_signature_input, build_signature_base, verify_signature
from ..pch.nonce_store import NonceStore
from ..receipts.store import ReceiptStore
from ..config import BINDING_HEADER

nonce_store = NonceStore()
_receipts = ReceiptStore()

# Metadata keys (HTTP/2 gRPC lowercase)
SIG_INPUT_KEY = 'signature-input'
SIG_KEY = 'signature'
CHALLENGE_KEY = 'pch-challenge'
BINDING_KEY = BINDING_HEADER.lower()
CHANNEL_BINDING_KEY = 'pch-channel-binding'
EVIDENCE_HASH_KEY = 'evidence-sha-256'

class ProtectedService(protected_pb2_grpc.ProtectedServicer):
    async def Call(self, request, context):  # type: ignore
        md = dict(context.invocation_metadata())
        sig_input = md.get(SIG_INPUT_KEY)
        signature = md.get(SIG_KEY)
        challenge = md.get(CHALLENGE_KEY)
        channel_binding = md.get(CHANNEL_BINDING_KEY, '')
        evidence_sha256_hex = md.get(EVIDENCE_HASH_KEY, '')
        client_ip = context.peer()  # format like ipv4:127.0.0.1:port
        route = '/grpc.Protected/Call'
        verified = False
        failure = 'missing_signature'
        receipt_id = None
        if not (sig_input and signature and challenge):
            # Issue challenge via trailing metadata (simple approach)
            nonce = nonce_store.issue(route=route, client_ip=client_ip, tls_id='grpc')
            await context.send_initial_metadata(((CHALLENGE_KEY, f':{nonce}:'),))
            return protected_pb2.ProtectedReply(ok=False, receipt_id='', pch_verified=False, failure_reason=failure)
        try:
            label, components, params = parse_signature_input(sig_input)
        except Exception:
            failure = 'bad_signature_input'
        else:
            # Build pseudo request shim
            class Rq:
                def __init__(self, md):
                    self.method = 'POST'
                    self.headers = {k.title(): v for k,v in md.items()}
                    class URL:
                        path = '/grpc.Protected/Call'
                        query = ''
                    self.url = URL()
            base = build_signature_base(Rq(md), components, params, evidence_sha256_hex)
            # Extract signature part
            sig_b64 = None
            for part in [p.strip() for p in signature.split(',') if '=' in p]:
                k,v = part.split('=',1)
                if v.startswith(':') and v.endswith(':'): v=v[1:-1]
                if k.strip()==label: sig_b64=v.strip()
            alg = params.get('alg','ed25519')
            keyid = params.get('keyid','')
            sig_ok = bool(sig_b64 and verify_signature(alg=alg, keyid=keyid, signature_b64=sig_b64, message=base))
            # Nonce
            presented_nonce = challenge[1:-1] if challenge.startswith(':') and challenge.endswith(':') else challenge
            nonce_ok = nonce_store.consume(route=route, client_ip=client_ip, tls_id='grpc', nonce=presented_nonce)
            binding_ok = True  # Simplified for gRPC demo (no TLS exporter propagation here)
            verified = bool(sig_ok and nonce_ok and binding_ok)
            failure = None if verified else ('bad_signature' if not sig_ok else ('nonce_replay' if not nonce_ok else 'bad_binding'))
        rec = _receipts.emit_enforcement_receipt(
            request=None,  # middleware path expects .headers; store gracefully handles None for pilot usage
            decision='allow' if verified else 'deny',
            reason='grpc_pch_ok' if verified else (failure or 'unknown'),
            pch={'present': True, 'verified': verified, 'failure_reason': failure, 'channel_binding': 'grpc-demo'},
        )
        receipt_id = rec.get('id')
        return protected_pb2.ProtectedReply(ok=verified, receipt_id=receipt_id, pch_verified=verified, failure_reason=failure or '')

async def serve(port: int = 50051):
    server = grpc.aio.server()
    protected_pb2_grpc.add_ProtectedServicer_to_server(ProtectedService(), server)
    server.add_insecure_port(f'[::]:{port}')
    await server.start()
    print(f'gRPC server listening on {port}')
    await server.wait_for_termination()

if __name__ == '__main__':
    asyncio.run(serve())
