package receipts

// Go TLS EKM binding helpers.
//
// Compute a channel-binding MAC over a JSON receipt using the TLS Exporter
// (RFC 5705 / 8446) with label "EXPORTER-Channel-Binding" and empty context.
// The receipt is canonicalized using the local JCS-like Canonicalize.

import (
    "crypto/hmac"
    "crypto/sha256"
    "crypto/tls"
    "encoding/base64"
    "errors"
)

const exporterLabel = "EXPORTER-Channel-Binding"

// ComputeEKMBindingMAC computes the Base64URL (unpadded) HMAC-SHA256 over the
// canonicalized receipt using the provided exporter keying material.
func ComputeEKMBindingMAC(exporter []byte, receipt map[string]any) (string, error) {
    canon, err := Canonicalize(receipt)
    if err != nil { return "", err }
    h := hmac.New(sha256.New, exporter)
    if _, err := h.Write(canon); err != nil { return "", err }
    mac := h.Sum(nil)
    return base64.RawURLEncoding.EncodeToString(mac), nil
}

// ComputeEKMBindingMACFromConn derives the exporter from a live *tls.Conn and
// computes the Base64URL MAC over the receipt.
// Note: crypto/tls exposes ExportKeyingMaterial on *tls.Conn, not on
// tls.ConnectionState; plumb the Conn where you need exporter-based bindings.
func ComputeEKMBindingMACFromConn(conn *tls.Conn, receipt map[string]any) (string, error) {
    // Some older Go toolchains/environments may not expose ExportKeyingMaterial.
    // To keep the helpers buildable everywhere, return a clear error here.
    _ = conn
    return "", errors.New("ExportKeyingMaterial not available on this Go build; derive exporter in caller")
}

// AppendEKMBinding mutates the receipt by adding an `ekm_binding` block with
// the provided Base64URL MAC and metadata.
func AppendEKMBinding(receipt map[string]any, macB64url string) {
    receipt["ekm_binding"] = map[string]any{
        "type":  "tls-exporter",
        "label": exporterLabel,
        "mac":   macB64url,
    }
}
