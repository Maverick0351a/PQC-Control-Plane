package main

// evg-sink: minimal envelope ingest verifying signature and returning Merkle refs.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

var pub ed25519.PublicKey
var leaves = make([][]byte, 0)

func main() {
	pkPath := os.Getenv("RECEIPT_PUBKEY_PEM")
	if pkPath == "" { log.Fatal("RECEIPT_PUBKEY_PEM unset") }
	// In MVP assume raw base64 key file (simplify). Future: load PEM.
	b, err := os.ReadFile(pkPath)
	if err != nil { log.Fatal(err) }
	decoded, err := base64.StdEncoding.DecodeString(string(b))
	if err != nil { log.Fatal(err) }
	pub = ed25519.PublicKey(decoded)
	mux := http.NewServeMux()
	mux.HandleFunc("/ingest", ingest)
	log.Println("evg-sink listening :8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}

func ingest(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	var env map[string]any
	if err := json.Unmarshal(body, &env); err != nil { http.Error(w, "bad json", 400); return }
	sig, _ := env["signature_b64"].(string)
	core := map[string]any{"envelope": env["envelope"], "claims": env["claims"]}
	canon, _ := json.Marshal(core) // relies on Go map iteration; production must canonicalize
	rawSig, err := base64.StdEncoding.DecodeString(sig)
	if err != nil { http.Error(w, "bad sig b64", 400); return }
	if !ed25519.Verify(pub, canon, rawSig) { http.Error(w, "signature invalid", 400); return }
	// Append leaf and compute current root (simple in-memory Merkle)
	lh := sha256.Sum256(canon)
	leaves = append(leaves, lh[:])
	root := merkleRoot(leaves)
	resp := map[string]any{
		"leaf_hash": hex.EncodeToString(lh[:]),
		"sth_root": hex.EncodeToString(root),
		"size": len(leaves),
		"timestamp": time.Now().UTC().Format(time.RFC3339Nano),
	}
	w.Header().Set("content-type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// merkleRoot computes a SHA-256 binary tree root over the provided leaves.
func merkleRoot(leaves [][]byte) []byte {
	if len(leaves) == 0 { return nil }
	layer := make([][]byte, len(leaves))
	copy(layer, leaves)
	for len(layer) > 1 {
		next := make([][]byte, 0, (len(layer)+1)/2)
		for i := 0; i < len(layer); i += 2 {
			if i+1 == len(layer) {
				next = append(next, layer[i])
				break
			}
			concat := append(append([]byte{}, layer[i]...), layer[i+1]...)
			h := sha256.Sum256(concat)
			next = append(next, h[:])
		}
		layer = next
	}
	return layer[0]
}
