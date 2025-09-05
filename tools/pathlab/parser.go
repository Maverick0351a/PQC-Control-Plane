// Package pathlab contains lightweight parsers for first-flight telemetry.
//
// This file provides a minimal TLS ClientHello parser using cryptobyte that:
// - Accepts one or more TLS records concatenated in buf (possibly fragmented)
// - Extracts the ClientHello handshake (spanning multiple records)
// - Returns the total handshake length, the SupportedGroups list, and whether
//   any group matches Kyber-hybrid codepoints (e.g., 0x11ec)
package pathlab

import (
    "encoding/binary"
    "errors"
    "fmt"

    "golang.org/x/crypto/cryptobyte"
)

// ParseClientHello parses a TLS ClientHello from buf.
// It returns:
// - totalLen: the complete handshake message length in bytes (4 + body),
// - groups: the SupportedGroups extension values if available,
// - hasKyberHybrid: true if any group ID is a Kyber-hybrid codepoint (e.g., 0x11ec).
// If the buffer does not yet contain the full handshake bytes, returns an
// io.ErrUnexpectedEOF-like error with totalLen set once determinable.
func ParseClientHello(buf []byte) (totalLen int, groups []uint16, hasKyberHybrid bool, err error) {
    // Need first TLS record header (5 bytes)
    if len(buf) < 5 {
        return 0, nil, false, errors.New("need at least 5 bytes for TLS record header")
    }
    // Parse first record header
    ct := buf[0] // should be 0x16 for Handshake
    if ct != 0x16 {
        return 0, nil, false, fmt.Errorf("unexpected content type: 0x%02x", ct)
    }
    // version := binary.BigEndian.Uint16(buf[1:3]) // legacy; not used here
    recLen := int(binary.BigEndian.Uint16(buf[3:5]))
    if recLen < 4 {
        return 0, nil, false, errors.New("record too short to contain handshake header")
    }
    if len(buf) < 5+recLen {
        // We at least need the first 5+4 bytes to read handshake header
        if len(buf) < 9 {
            return 0, nil, false, errors.New("insufficient for handshake header")
        }
    }
    // Handshake header is at start of first record fragment
    if len(buf) < 9 {
        return 0, nil, false, errors.New("insufficient for handshake header")
    }
    hsType := buf[5]
    if hsType != 0x01 { // client_hello
        return 0, nil, false, fmt.Errorf("unexpected handshake type: 0x%02x", hsType)
    }
    bodyLen := int(buf[6])<<16 | int(buf[7])<<8 | int(buf[8])
    totalLen = 4 + bodyLen

    // Accumulate handshake bytes across records until totalLen is satisfied
    need := totalLen
    var hs []byte
    off := 0
    for off < len(buf) && need > 0 {
        if off+5 > len(buf) {
            break
        }
        if buf[off] != 0x16 {
            break
        }
        rlen := int(binary.BigEndian.Uint16(buf[off+3 : off+5]))
        fragStart := off + 5
        fragEnd := fragStart + rlen
        if fragEnd > len(buf) {
            // partial fragment available
            fragEnd = len(buf)
        }
        // Copy from fragment up to remaining "need" bytes
        frag := buf[fragStart:fragEnd]
        if len(hs) == 0 {
            // On the first fragment, ensure we start from the handshake start
            hs = append(hs, frag...)
        } else {
            hs = append(hs, frag...)
        }
        need = totalLen - len(hs)
        off = fragStart + rlen
    }
    if len(hs) < totalLen {
        // Not enough data yet; return totalLen so caller can buffer up to this
        return totalLen, nil, false, errors.New("incomplete handshake; buffer more data")
    }

    // Parse the ClientHello body (skip the 4-byte handshake header)
    body := hs[4:totalLen]
    s := cryptobyte.String(body)

    // legacy_version (2)
    var legacyVersion uint16
    if !s.ReadUint16(&legacyVersion) {
        return totalLen, nil, false, errors.New("failed to read legacy_version")
    }
    // random (32)
    if !s.Skip(32) {
        return totalLen, nil, false, errors.New("failed to skip random")
    }
    // legacy_session_id
    var sessionID cryptobyte.String
    if !s.ReadUint8LengthPrefixed(&sessionID) {
        return totalLen, nil, false, errors.New("failed to read session_id")
    }
    // cipher_suites
    var cipherSuites cryptobyte.String
    if !s.ReadUint16LengthPrefixed(&cipherSuites) {
        return totalLen, nil, false, errors.New("failed to read cipher_suites")
    }
    // compression_methods
    var comp cryptobyte.String
    if !s.ReadUint8LengthPrefixed(&comp) {
        return totalLen, nil, false, errors.New("failed to read compression_methods")
    }
    // extensions
    var exts cryptobyte.String
    if !s.ReadUint16LengthPrefixed(&exts) {
        // No extensions: return what we have (empty groups)
        return totalLen, nil, false, nil
    }
    for !exts.Empty() {
        var extType uint16
        var extData cryptobyte.String
        if !exts.ReadUint16(&extType) || !exts.ReadUint16LengthPrefixed(&extData) {
            break
        }
        if extType == 0x000a { // supported_groups
            var list cryptobyte.String
            if !extData.ReadUint16LengthPrefixed(&list) {
                continue
            }
            for !list.Empty() {
                var g uint16
                if !list.ReadUint16(&g) {
                    break
                }
                groups = append(groups, g)
                if isKyberHybridGroup(g) {
                    hasKyberHybrid = true
                }
            }
        }
    }
    return totalLen, groups, hasKyberHybrid, nil
}

// isKyberHybridGroup returns true if the NamedGroup id is a known Kyber-hybrid codepoint.
// This includes draft values such as 0x11ec. Extend as needed when new codepoints appear.
func isKyberHybridGroup(id uint16) bool {
    switch id {
    case 0x11ec: // example: X25519+Kyber768 hybrid (draft codepoint)
        return true
    }
    // Optionally recognize a small range reserved for hybrids
    if id >= 0x11ec && id <= 0x11ff {
        return true
    }
    return false
}
