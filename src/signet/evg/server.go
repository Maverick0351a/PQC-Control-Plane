package main

// EVG (Evidence Graph) bootstrap server.
// Minimal ingestion + Merkle root publication + verification endpoint.
// Endpoints:
//  POST /ingest  (body: arbitrary JSON receipt) -> {status, size, root}
//  GET  /sth     -> {log_id, size, root, epoch}
//  POST /__evg/verify {receipt:<obj>} -> {present:bool, leaf_hash, size, root}
//  GET  /__health
//  (optional) GET /__compliance-pack.zip -> 501 placeholder

import (
    "crypto/sha256"
    "encoding/base64"
    "encoding/json"
    "log"
    "net/http"
    "os"
    "sync"
    "time"

    cbor "github.com/fxamacker/cbor/v2"
)

type Leaf struct {
    Raw       json.RawMessage
    HashBytes [32]byte
    Format    string // "vdc" or "legacy"
    EntryID   string // optional
}

type LogState struct {
    mu    sync.RWMutex
    leaves []Leaf
    logID string
}

var vdcMagic = []byte{0x89, 'v', 'd', 'c', 0x0d, 0x0a, 0x1a, 0x0a}

// computeVdcLeafHash tries to parse a VDC blob and extract the SigBase from the first COSE_Sign1 receipt.
// It returns (hash, true) on success. On failure, (zero, false).
func computeVdcLeafHash(vdc []byte) ([32]byte, bool) {
    var zero [32]byte
    if len(vdc) < len(vdcMagic) || string(vdc[:len(vdcMagic)]) != string(vdcMagic) {
        return zero, false
    }
    // Decode VDC CBOR body (top-level map). We only need key 4 (receipts: list of bstr COSE_Sign1).
    var top map[int]any
    if err := cbor.Unmarshal(vdc[len(vdcMagic):], &top); err != nil {
        return zero, false
    }
    recVal, ok := top[4]
    if !ok {
        return zero, false
    }
    recList, ok := recVal.([]any)
    if !ok || len(recList) == 0 {
        return zero, false
    }
    rec0, ok := recList[0].([]byte)
    if !ok || len(rec0) == 0 {
        return zero, false
    }
    // COSE_Sign1 structure: [protected_bstr, unprotected_map, payload:bstr, signature:bstr]
    var cose []any
    if err := cbor.Unmarshal(rec0, &cose); err != nil {
        return zero, false
    }
    if len(cose) != 4 {
        return zero, false
    }
    payload, ok := cose[2].([]byte)
    if !ok {
        return zero, false
    }
    h := sha256.Sum256(payload)
    return h, true
}

func (ls *LogState) append(raw json.RawMessage, format string, entryID string) (size int, root string, leafHash string) {
    ls.mu.Lock()
    defer ls.mu.Unlock()
    // Prefer VDC SigBase hash if format=="vdc" and payload contains SigBase
    var h [32]byte
    if format == "vdc" {
        if hv, ok := computeVdcLeafHash([]byte(raw)); ok {
            h = hv
        } else {
            // Fallback to hashing raw bytes if parsing fails
            h = sha256.Sum256([]byte(raw))
        }
    } else {
        h = sha256.Sum256(raw)
    }
    ls.leaves = append(ls.leaves, Leaf{Raw: raw, HashBytes: h, Format: format, EntryID: entryID})
    size = len(ls.leaves)
    root = ls.computeRootLocked()
    leafHash = base64.StdEncoding.EncodeToString(h[:])
    return
}

func (ls *LogState) computeRootLocked() string {
    if len(ls.leaves) == 0 { return "" }
    // Simple balanced recompute each time (O(n)); fine for MVP scale.
    hashes := make([][]byte, len(ls.leaves))
    for i,l := range ls.leaves { h := l.HashBytes; hashes[i] = h[:] }
    for len(hashes) > 1 {
        var next [][]byte
        for i := 0; i < len(hashes); i+=2 {
            if i+1 == len(hashes) { // odd
                next = append(next, hashes[i])
            } else {
                b := append(hashes[i], hashes[i+1]...)
                hh := sha256.Sum256(b)
                next = append(next, hh[:])
            }
        }
        hashes = next
    }
    return base64.StdEncoding.EncodeToString(hashes[0])
}

func (ls *LogState) rootSnapshot() (size int, root string) {
    ls.mu.RLock(); defer ls.mu.RUnlock()
    size = len(ls.leaves)
    root = ls.computeRootLocked()
    return
}

func (ls *LogState) verify(raw json.RawMessage) (present bool, leafHash string, size int, root string) {
    // If the input looks like a VDC, compute leaf hash over SigBase; otherwise over raw JSON bytes.
    var h [32]byte
    if hv, ok := computeVdcLeafHash([]byte(raw)); ok {
        h = hv
    } else {
        h = sha256.Sum256(raw)
    }
    leafHash = base64.StdEncoding.EncodeToString(h[:])
    ls.mu.RLock(); defer ls.mu.RUnlock()
    for _, l := range ls.leaves { if l.HashBytes == h { present = true; break } }
    size = len(ls.leaves)
    root = ls.computeRootLocked()
    return
}

type proofElem struct {
    Sibling string `json:"sibling"`
    Position string `json:"position"` // "left" or "right"
}

// computeAuditPathLocked returns the Merkle audit path for a given leaf index.
// It must be called with ls.mu held (RLock or Lock) since it inspects ls.leaves.
func (ls *LogState) computeAuditPathLocked(index int) (proof []proofElem, ok bool) {
    n := len(ls.leaves)
    if index < 0 || index >= n { return nil, false }
    // Build initial level of hashes
    level := make([][32]byte, n)
    for i,l := range ls.leaves { level[i] = l.HashBytes }
    idx := index
    for len(level) > 1 {
        // if odd count, last carries over
        var next [][32]byte
        for i := 0; i < len(level); i += 2 {
            if i+1 == len(level) {
                // carry
                next = append(next, level[i])
                if i == idx { // no sibling at this level
                    // no proof element when no sibling; parent is just carry
                }
                continue
            }
            // pair i,i+1
            if idx == i || idx == i+1 {
                if idx == i { // our node is left; sibling is right (i+1)
                    pe := proofElem{Sibling: base64.StdEncoding.EncodeToString(level[i+1][:]), Position: "right"}
                    proof = append(proof, pe)
                } else { // idx == i+1; our node right; sibling left
                    pe := proofElem{Sibling: base64.StdEncoding.EncodeToString(level[i][:]), Position: "left"}
                    proof = append(proof, pe)
                }
            }
            b := append(level[i][:], level[i+1][:]...)
            hh := sha256.Sum256(b)
            next = append(next, hh)
        }
        // move up one level
        if len(level)%2 == 1 && idx == len(level)-1 {
            // carried to next at position len(next)-1
            idx = len(next)-1
        } else {
            idx = idx / 2
        }
        level = next
    }
    return proof, true
}

// findLeafIndex finds the index of a leaf by base64-encoded hash.
func (ls *LogState) findLeafIndex(leafB64 string) int {
    bs, err := base64.StdEncoding.DecodeString(leafB64)
    if err != nil || len(bs) != 32 { return -1 }
    var h32 [32]byte
    copy(h32[:], bs)
    ls.mu.RLock(); defer ls.mu.RUnlock()
    for i,l := range ls.leaves {
        if l.HashBytes == h32 { return i }
    }
    return -1
}

func main(){
    port := os.Getenv("EVG_PORT")
    if port == "" { port = "8088" }
    state := &LogState{logID: "evg"}

    mux := http.NewServeMux()
    mux.HandleFunc("/__health", func(w http.ResponseWriter, r *http.Request){
        w.Header().Set("Content-Type","application/json");
        w.Write([]byte(`{"status":"ok"}`))
    })
    mux.HandleFunc("/sth", func(w http.ResponseWriter, r *http.Request){
        size, root := state.rootSnapshot()
        obj := map[string]any{"log_id": state.logID, "size": size, "root": root, "epoch": time.Now().UTC().Format("2006-01-02")}
        enc(w,obj)
    })
    mux.HandleFunc("/ingest", func(w http.ResponseWriter, r *http.Request){
        defer r.Body.Close()
        var body map[string]any
        if err := json.NewDecoder(r.Body).Decode(&body); err != nil { http.Error(w, err.Error(), 400); return }
        format, _ := body["format"].(string)
        if format == "vdc" {
            b64, _ := body["vdc_b64"].(string)
            entryID, _ := body["entry_id"].(string)
            bs, err := base64.StdEncoding.DecodeString(b64)
            if err != nil { http.Error(w, err.Error(), 400); return }
            // Store raw bytes as JSON string for MVP visibility
            raw := json.RawMessage(bs)
            size, root, leaf := state.append(raw, "vdc", entryID)
            enc(w, map[string]any{"status":"ok","size":size,"root":root,"leaf_hash":leaf,"format":"vdc","entry_id":entryID})
            return
        }
        // Legacy fallback: accept any JSON object
        payload := body["payload"]
        raw, err := json.Marshal(payload)
        if err != nil { http.Error(w, err.Error(), 400); return }
        size, root, leaf := state.append(raw, "legacy", "")
        enc(w, map[string]any{"status":"ok","size":size,"root":root,"leaf_hash":leaf,"format":"legacy"})
    })
    mux.HandleFunc("/__evg/verify", func(w http.ResponseWriter, r *http.Request){
        defer r.Body.Close()
        var body struct { Receipt json.RawMessage `json:"receipt"` }
        if err := json.NewDecoder(r.Body).Decode(&body); err != nil { http.Error(w, err.Error(),400); return }
        present, leaf, size, root := state.verify(body.Receipt)
        enc(w, map[string]any{"present":present,"leaf_hash":leaf,"size":size,"root":root})
    })
    mux.HandleFunc("/__evg/proof", func(w http.ResponseWriter, r *http.Request){
        switch r.Method {
        case http.MethodGet:
            leaf := r.URL.Query().Get("leaf")
            if leaf == "" { http.Error(w, "missing leaf", 400); return }
            state.mu.RLock()
            idx := state.findLeafIndex(leaf)
            size := len(state.leaves)
            root := state.computeRootLocked()
            if idx < 0 { state.mu.RUnlock(); enc(w, map[string]any{"present":false,"leaf_hash":leaf,"size":size,"root":root}); return }
            proof, _ := state.computeAuditPathLocked(idx)
            state.mu.RUnlock()
            enc(w, map[string]any{"present":true,"leaf_hash":leaf,"index":idx,"size":size,"root":root,"proof":proof})
        case http.MethodPost:
            defer r.Body.Close()
            var body struct { Receipt json.RawMessage `json:"receipt"` }
            if err := json.NewDecoder(r.Body).Decode(&body); err != nil { http.Error(w, err.Error(),400); return }
            // Compute leaf hash using VDC SigBase if applicable
            var h [32]byte
            if hv, ok := computeVdcLeafHash([]byte(body.Receipt)); ok {
                h = hv
            } else {
                h = sha256.Sum256(body.Receipt)
            }
            leaf := base64.StdEncoding.EncodeToString(h[:])
            state.mu.RLock()
            // linear scan to find index
            idx := -1
            for i,l := range state.leaves { if l.HashBytes == h { idx = i; break } }
            size := len(state.leaves)
            root := state.computeRootLocked()
            var proof []proofElem
            if idx >= 0 {
                proof, _ = state.computeAuditPathLocked(idx)
            }
            state.mu.RUnlock()
            enc(w, map[string]any{"present": idx>=0, "leaf_hash":leaf, "index":idx, "size":size, "root":root, "proof":proof})
        default:
            http.Error(w, "method not allowed", 405)
        }
    })
    mux.HandleFunc("/__compliance-pack.zip", func(w http.ResponseWriter, r *http.Request){
        http.Error(w, "not implemented", http.StatusNotImplemented)
    })

    log.Printf("[evg] listening on :%s", port)
    if err := http.ListenAndServe(":"+port, mux); err != nil { log.Fatal(err) }
}

func enc(w http.ResponseWriter, v any) {
    w.Header().Set("Content-Type","application/json")
    _ = json.NewEncoder(w).Encode(v)
}
