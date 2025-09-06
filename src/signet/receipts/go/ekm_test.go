package receipts

import (
    "encoding/base64"
    "testing"
)

func TestComputeEKMBindingMAC_Deterministic(t *testing.T) {
    // Use a dummy exporter and a simple receipt map
    exporter := make([]byte, 32)
    for i := range exporter { exporter[i] = byte(i) }
    receipt := map[string]any{"a": 1, "b": "x"}
    mac, err := ComputeEKMBindingMAC(exporter, receipt)
    if err != nil { t.Fatalf("err: %v", err) }
    if mac == "" { t.Fatal("empty mac") }
    // Ensure it is valid Base64URL
    if _, err := base64.RawURLEncoding.DecodeString(mac); err != nil {
        t.Fatalf("not base64url: %v", err)
    }
    AppendEKMBinding(receipt, mac)
    if receipt["ekm_binding"] == nil { t.Fatalf("missing ekm_binding block") }
}
