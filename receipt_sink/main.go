package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/spf13/pflag"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// DPRRecord mirrors the JSON produced by the WASM signer (subset needed for indexing)
// {v, ts, method, path, cb, req_sha384, rsp_sha384, hmac_tag?, ekm_tag?}

type DPRRecord struct {
	V         int    `json:"v"`
	TS        int64  `json:"ts"`
	Method    string `json:"method"`
	Path      string `json:"path"`
	CB        string `json:"cb"`
	ReqSHA384 string `json:"req_sha384"`
	RspSHA384 string `json:"rsp_sha384"`
	HMACTag   string `json:"hmac_tag,omitempty"`
	EKMTag    string `json:"ekm_tag,omitempty"`
}

type IngestRequest struct {
	Record DPRRecord `json:"record"`
	SigB64 string    `json:"signature"`
	KeyID  string    `json:"key_id"`
}

type IngestResponse struct {
	Status   string `json:"status"`
	LeafHash string `json:"leaf_hash"`
	STH      *STH   `json:"sth,omitempty"`
}

// Simple in-memory Merkle tree batching once per minute.

type merkleBatcher struct {
	mu      sync.Mutex
	leaves  [][]byte
	lastSTH *STH
	interval time.Duration
	lastFlush time.Time
}

type STH struct {
	Size      int    `json:"size"`
	RootHash  string `json:"root_hash"`
	Timestamp int64  `json:"ts"`
}

func newBatcher(interval time.Duration) *merkleBatcher {
	b := &merkleBatcher{interval: interval}
	go b.loop()
	return b
}

func (m *merkleBatcher) loop() {
	ticker := time.NewTicker(m.interval)
	for range ticker.C { m.flush() }
}

func (m *merkleBatcher) add(leaf []byte) (leafHash string, sth *STH) {
	m.mu.Lock()
	defer m.mu.Unlock()
	h := sha256.Sum256(leaf)
	leafHash = hex.EncodeToString(h[:])
	m.leaves = append(m.leaves, h[:])
	return leafHash, m.lastSTH
}

func (m *merkleBatcher) flush() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.leaves) == 0 { return }
	root := buildMerkleRoot(m.leaves)
	sth := &STH{Size: len(m.leaves), RootHash: hex.EncodeToString(root), Timestamp: time.Now().Unix()}
	m.lastSTH = sth
	m.leaves = nil
	m.lastFlush = time.Now()
}

func buildMerkleRoot(leaves [][]byte) []byte {
	if len(leaves) == 1 { return leaves[0] }
	var level [][]byte
	for i:=0;i<len(leaves);i+=2 { if i+1 < len(leaves) { h:=sha256.Sum256(append(leaves[i], leaves[i+1]...)); level = append(level, h[:]) } else { level = append(level, leaves[i]) } }
	return buildMerkleRoot(level)
}

// Storage abstraction (SQLite or ClickHouse)

type storage interface { insert(record DPRRecord, sig string, keyID string, leafHash string, corrKey string) error }

type sqliteStore struct { db *sql.DB }
func (s *sqliteStore) insert(r DPRRecord, sig, keyID, leaf, corrKey string) error {
	_, err := s.db.Exec(`INSERT INTO dpr (ts, method, path, cb, req_sha384, rsp_sha384, hmac_tag, ekm_tag, signature, key_id, leaf_hash, corr_key) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`, r.TS, r.Method, r.Path, r.CB, r.ReqSHA384, r.RspSHA384, nullable(r.HMACTag), nullable(r.EKMTag), sig, keyID, leaf, corrKey)
	return err
}

func nullable(s string) any { if s=="" { return nil }; return s }

func initSQLite(path string) (*sqliteStore, error) {
	db, err := sql.Open("sqlite3", path)
	if err != nil { return nil, err }
	ddl := `CREATE TABLE IF NOT EXISTS dpr(
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		ts INTEGER,
		method TEXT,
		path TEXT,
		cb TEXT,
		req_sha384 TEXT,
		rsp_sha384 TEXT,
		hmac_tag TEXT,
		ekm_tag TEXT,
		signature TEXT,
		key_id TEXT,
		leaf_hash TEXT,
		corr_key TEXT
	);
	CREATE TABLE IF NOT EXISTS decisions(
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		ts INTEGER,
		corr_key TEXT,
		pqc_enabled INTEGER,
		hybrid_failed INTEGER,
		path TEXT,
		route TEXT
	);
	CREATE INDEX IF NOT EXISTS idx_decisions_corr ON decisions(corr_key);
	CREATE INDEX IF NOT EXISTS idx_dpr_corr ON dpr(corr_key);`
	if _, err := db.Exec(ddl); err != nil { return nil, err }
	return &sqliteStore{db: db}, nil
}

// insert decision row
func (s *sqliteStore) insertDecision(dec DecisionIngest) error {
	_, err := s.db.Exec(`INSERT INTO decisions (ts, corr_key, pqc_enabled, hybrid_failed, path, route) VALUES (?,?,?,?,?,?)`, dec.TS, dec.CorrKey, btoi(dec.PQCEnabled), btoi(dec.HybridFailed), dec.Path, dec.Route)
	return err
}

func (s *sqliteStore) topFvar(limit int) ([]FVarRow, error) {
	rows, err := s.db.Query(`SELECT COALESCE(dpr.path, decisions.path) as dataset, COUNT(*) as exposure
	FROM dpr LEFT JOIN decisions USING(corr_key)
	WHERE decisions.corr_key IS NOT NULL AND (decisions.pqc_enabled=0 OR decisions.hybrid_failed=1)
	GROUP BY dataset ORDER BY exposure DESC LIMIT ?`, limit)
	if err != nil { return nil, err }
	defer rows.Close()
	var out []FVarRow
	for rows.Next() { var r FVarRow; if err := rows.Scan(&r.Dataset, &r.Exposure); err != nil { return nil, err }; out = append(out, r) }
	return out, nil
}

// ClickHouse backend removed in initial minimal implementation.

// Signature verification utilities

func verifyRecordSig(rec DPRRecord, sigB64 string, pub ed25519.PublicKey) error {
	// Canonical JSON must match signer (serde_json order) - rebuild struct ordering.
	b, err := json.Marshal(rec)
	if err != nil { return err }
	sigRaw, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil { return err }
	if len(sigRaw) != ed25519.SignatureSize { return errors.New("bad signature length") }
	if !ed25519.Verify(pub, b, sigRaw) { return errors.New("signature invalid") }
	return nil
}

// For demo we load single Ed25519 public key from env (BASE64 of 32B pubkey)

func loadPubKey() (ed25519.PublicKey, error) {
	b64 := os.Getenv("DPR_PUBKEY_B64")
	if b64 == "" { return nil, errors.New("DPR_PUBKEY_B64 unset") }
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil { return nil, err }
	if len(raw) != ed25519.PublicKeySize { return nil, errors.New("bad pubkey length") }
	return ed25519.PublicKey(raw), nil
}

// Basic ekm_tag form validation (hex 64 chars = 32B) & channel binding base64 decodes.

func validateBinding(rec DPRRecord) error {
	if rec.CB == "" { return errors.New("missing channel binding") }
	if _, err := base64.StdEncoding.DecodeString(rec.CB); err != nil { return fmt.Errorf("cb not b64: %w", err) }
	if rec.EKMTag != "" {
		if len(rec.EKMTag) != 64 { return errors.New("ekm_tag length") }
		if _, err := hex.DecodeString(rec.EKMTag); err != nil { return fmt.Errorf("ekm_tag hex: %w", err) }
	}
	return nil
}

// Decision ingestion structures & helpers
type DecisionIngest struct {
	TS           int64  `json:"ts"`
	CorrKey      string `json:"corr_key,omitempty"`
	EKMTag       string `json:"ekm_tag,omitempty"`
	CB           string `json:"cb,omitempty"`
	PQCEnabled   bool   `json:"pqc_enabled"`
	HybridFailed bool   `json:"hybrid_failed"`
	Path         string `json:"path,omitempty"`
	Route        string `json:"route,omitempty"`
}

type FVarRow struct {
	Dataset  string `json:"dataset"`
	Exposure int    `json:"exposure"`
}

func btoi(b bool) int { if b { return 1 }; return 0 }

func deriveCorrKey(ekmTag, cb string) (string, error) {
	if ekmTag != "" { if len(ekmTag) == 64 { return ekmTag, nil }; return "", errors.New("bad ekm length") }
	if cb == "" { return "", errors.New("no correlation material") }
	raw, err := base64.StdEncoding.DecodeString(cb)
	if err != nil { return "", err }
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:]), nil
}

func main() {
	var bind, sqlitePath, backend string
	pflag.StringVar(&bind, "bind", ":8081", "listen address")
	pflag.StringVar(&sqlitePath, "sqlite", "dpr.db", "sqlite database path")
	pflag.StringVar(&backend, "backend", "sqlite", "storage backend: sqlite|clickhouse (clickhouse TODO)")
	pflag.Parse()

	pub, err := loadPubKey()
	if err != nil { log.Fatalf("load pubkey: %v", err) }

	if backend != "sqlite" {
		log.Fatalf("backend %s not implemented (only sqlite for now)", backend)
	}
	st, err := initSQLite(sqlitePath)
	if err != nil { log.Fatalf("sqlite init: %v", err) }
	store := storage(st)

	batcher := newBatcher(time.Minute)

	// Metrics
	dprTotal := prometheus.NewCounter(prometheus.CounterOpts{Name:"dpcp_dpr_total", Help:"Total DPR records ingested"})
	ekmAvail := prometheus.NewCounter(prometheus.CounterOpts{Name:"dpcp_ekm_present_total", Help:"DPRs with ekm_tag present"})
	bytesHashed := prometheus.NewCounter(prometheus.CounterOpts{Name:"dpcp_bytes_hashed_total", Help:"Total bytes counted toward hashing (req+rsp)"})
	sthLag := prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name:"dpcp_sth_age_seconds", Help:"Seconds since last STH flush"}, func() float64 {
		if batcher.lastFlush.IsZero() {
			return 0
		}
		return time.Since(batcher.lastFlush).Seconds()
	})
	exposureGauge := prometheus.NewGauge(prometheus.GaugeOpts{Name:"dpcp_top_exposure_first", Help:"Exposure count of top dataset (debug)"})
	prometheus.MustRegister(dprTotal, ekmAvail, bytesHashed, sthLag, exposureGauge)

	http.HandleFunc("/ingest", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost { http.Error(w, "method", http.StatusMethodNotAllowed); return }
		var req IngestRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil { http.Error(w, "bad json", 400); return }
		if err := validateBinding(req.Record); err != nil { http.Error(w, "binding", 400); return }
		if err := verifyRecordSig(req.Record, req.SigB64, pub); err != nil { http.Error(w, "sig", 400); return }
		corr, _ := deriveCorrKey(req.Record.EKMTag, req.Record.CB)
		leaf := mustJSON(req.Record)
		leafHash, sth := batcher.add(leaf)
		// simplistic bytes hashed approximation: length of leaf JSON (req+rsp already hashed upstream)
		bytesHashed.Add(float64(len(leaf)))
		dprTotal.Inc()
		if req.Record.EKMTag != "" { ekmAvail.Inc() }
		if err := store.insert(req.Record, req.SigB64, req.KeyID, leafHash, corr); err != nil { log.Printf("insert err: %v", err); http.Error(w, "store", 500); return }
		resp := IngestResponse{Status: "ok", LeafHash: leafHash, STH: sth}
		w.Header().Set("content-type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	http.HandleFunc("/decision", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost { http.Error(w, "method", http.StatusMethodNotAllowed); return }
		var dec DecisionIngest
		if err := json.NewDecoder(r.Body).Decode(&dec); err != nil { http.Error(w, "bad json", 400); return }
		if dec.TS == 0 { dec.TS = time.Now().Unix() }
		if dec.CorrKey == "" {
			var err error
			dec.CorrKey, err = deriveCorrKey(dec.EKMTag, dec.CB)
			if err != nil { http.Error(w, "corr", 400); return }
		}
		if s, ok := store.(*sqliteStore); ok { if err := s.insertDecision(dec); err != nil { http.Error(w, "store", 500); return } }
		w.Header().Set("content-type", "application/json")
		w.Write([]byte(`{"status":"ok"}`))
	})

	http.HandleFunc("/fvar", func(w http.ResponseWriter, r *http.Request) {
		lim := 10
		if q := r.URL.Query().Get("limit"); q != "" { if v, err := strconv.Atoi(q); err==nil { lim = v } }
		var rows []FVarRow
		if s, ok := store.(*sqliteStore); ok {
			var err error
			rows, err = s.topFvar(lim)
			if err != nil { http.Error(w, "query", 500); return }
			if len(rows) > 0 { exposureGauge.Set(float64(rows[0].Exposure)) }
		}
		w.Header().Set("content-type", "application/json")
		json.NewEncoder(w).Encode(rows)
	})

	http.Handle("/metrics", promhttp.Handler())

	log.Printf("receipt sink listening on %s (backend=%s)", bind, backend)
	log.Fatal(http.ListenAndServe(bind, nil))
}

func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }
