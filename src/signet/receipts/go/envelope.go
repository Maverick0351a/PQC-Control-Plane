package receipts

// Envelope v1 (Go reference) - minimal skeleton for future migration of Python receipt path.
// Handles JCS-like canonicalization (restricted) and Ed25519 signing/verification.
// NOTE: This is a placeholder; full implementation (stream canonicalization, HKDF variant) pending.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sort"
)

// Canonicalize performs a minimal JSON canonicalization matching the Python jcs_canonicalize
// (sort keys, no extra whitespace, UTF-8 preserved). Numbers and floats avoided.
func Canonicalize(v any) ([]byte, error) {
	return marshalSorted(v)
}

// marshalSorted recursively sorts map keys.
func marshalSorted(v any) ([]byte, error) {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t { keys = append(keys, k) }
		sort.Strings(keys)
		m := make(map[string]any, len(t))
		for _, k := range keys { m[k] = t[k] }
		return json.Marshal(m)
	case []any:
		arr := make([]any, len(t))
		for i, e := range t { arr[i] = e }
		return json.Marshal(arr)
	default:
		return json.Marshal(t)
	}
}

// BuildAndSign constructs the envelope and returns JSON + signature b64.
func BuildAndSign(priv ed25519.PrivateKey, env map[string]any, claims map[string]any) (map[string]any, error) {
	obj := map[string]any{"envelope": env, "claims": claims}
	canon, err := Canonicalize(obj)
	if err != nil { return nil, err }
	sig := ed25519.Sign(priv, canon)
	obj["signature_b64"] = base64.StdEncoding.EncodeToString(sig)
	return obj, nil
}

func Verify(pub ed25519.PublicKey, obj map[string]any) error {
	sigB64, ok := obj["signature_b64"].(string)
	if !ok { return errors.New("missing signature_b64") }
	copyObj := map[string]any{"envelope": obj["envelope"], "claims": obj["claims"]}
	canon, err := Canonicalize(copyObj)
	if err != nil { return err }
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil { return err }
	if !ed25519.Verify(pub, canon, sig) { return errors.New("bad signature") }
	return nil
}

// DeriveBindingTag demonstrates the binding MAC derivation (not exported for now).
func DeriveBindingTag(exporter []byte, claims map[string]any) (string, error) {
	canon, err := Canonicalize(claims)
	if err != nil { return "", err }
	// HKDF-Expand single block simplification (exporter as PRK) + HMAC(PRK, info||0x01)
	info := []byte("Signet-Receipt-Bind/v1")
	h := sha256.New
	macKey := hmacSingleExpand(exporter, info) // 32 bytes
	mac := hmac(macKey, canon)
	return base64.StdEncoding.EncodeToString(mac), nil
}

func hmacSingleExpand(prk, info []byte) []byte {
	b := append(info, 0x01)
	h := sha256.New()
	h.Write(prk)
	h.Write(b)
	return h.Sum(nil)
}

func hmac(key, data []byte) []byte {
	h := sha256.New()
	h.Write(key)
	h.Write(data)
	return h.Sum(nil)
}
