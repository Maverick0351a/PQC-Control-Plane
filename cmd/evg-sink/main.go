package main

// evg-sink: minimal envelope ingest verifying signature and returning Merkle refs.

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
)

var pub ed25519.PublicKey

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
	// Merkle append placeholder
	resp := map[string]any{"leaf_hash": "TODO", "sth_id": "TODO"}
	w.Header().Set("content-type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
