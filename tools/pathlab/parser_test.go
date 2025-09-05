package pathlab

import (
    "encoding/binary"
    "testing"
)

// build a minimal TLS ClientHello with supported_groups {0x001d, 0x11ec}
func buildCH() []byte {
    // Handshake body
    body := make([]byte, 0)
    // legacy_version
    body = append(body, 0x03, 0x03)
    // random
    body = append(body, make([]byte, 32)...)
    // session_id (empty)
    body = append(body, 0x00)
    // cipher_suites (empty)
    body = append(body, 0x00, 0x00)
    // compression_methods (empty)
    body = append(body, 0x01, 0x00)
    // extensions start
    exts := make([]byte, 0)
    // supported_groups ext type 0x000a
    sg := make([]byte, 0)
    // list length = 4 bytes (two groups)
    sg = append(sg, 0x00, 0x04)
    // x25519(0x001d), kyber-hybrid(0x11ec)
    sg = append(sg, 0x00, 0x1d, 0x11, 0xec)
    // ext: type + length + body
    ext := make([]byte, 0)
    ext = append(ext, 0x00, 0x0a)
    ext = append(ext, 0x00, byte(len(sg)))
    ext = append(ext, sg...)
    exts = append(exts, ext...)
    // prepend total extensions length
    extsLen := make([]byte, 2)
    binary.BigEndian.PutUint16(extsLen, uint16(len(exts)))
    body = append(body, extsLen...)
    body = append(body, exts...)

    // Handshake header: type(1)=client_hello, len(3)
    hs := make([]byte, 0, 4+len(body))
    hs = append(hs, 0x01)
    hs = append(hs, byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
    hs = append(hs, body...)

    // TLS record header: type(1)=handshake, version(2), length(2)
    rec := make([]byte, 5)
    rec[0] = 0x16
    rec[1], rec[2] = 0x03, 0x03
    binary.BigEndian.PutUint16(rec[3:5], uint16(len(hs)))
    return append(rec, hs...)
}

func TestParseClientHello_Groups(t *testing.T) {
    buf := buildCH()
    total, groups, hasKyber, err := ParseClientHello(buf)
    if err != nil { t.Fatalf("unexpected err: %v", err) }
    if total != len(buf)-5 { // total handshake length excludes 5-byte record header
        t.Fatalf("unexpected total length: %d", total)
    }
    if len(groups) != 2 { t.Fatalf("want 2 groups, got %d", len(groups)) }
    if !hasKyber { t.Fatalf("expected kyber-hybrid detection") }
}

func TestParseClientHello_Incomplete(t *testing.T) {
    buf := buildCH()
    // Truncate to just the first 9 bytes (record header + hs header)
    partial := buf[:9]
    _, _, _, err := ParseClientHello(partial)
    if err == nil { t.Fatalf("expected error for incomplete buffer") }
}
