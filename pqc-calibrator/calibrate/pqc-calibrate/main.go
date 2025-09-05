package main

import (
    "encoding/json"
    "errors"
    "flag"
    "fmt"
    "log"
    "net/http"
    "os"
    "path/filepath"
    "strings"
    "time"
)

type RunSpec struct {
    Target            string   `json:"target"`
    Profiles          []string `json:"profiles"`
    Impairments       []string `json:"impairments"`
    HeaderBudgetBytes int      `json:"header_budget_bytes"`
}

type RunResult struct {
    ID        string    `json:"id"`
    Started   time.Time `json:"started"`
    Finished  time.Time `json:"finished"`
    Spec      RunSpec   `json:"spec"`
    Summary   string    `json:"summary"`
}

func writeJSON(path string, v any) error {
    if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil { return err }
    f, err := os.Create(path)
    if err != nil { return err }
    defer f.Close()
    enc := json.NewEncoder(f)
    enc.SetIndent("", "  ")
    return enc.Encode(v)
}

func cmdRun(args []string) error {
    fs := flag.NewFlagSet("run", flag.ContinueOnError)
    var target string
    var profilesCSV string
    var impCSV string
    var headerBudget int
    var outDir string
    fs.StringVar(&target, "target", "", "Target base URL")
    fs.StringVar(&profilesCSV, "profiles", "", "Comma-separated profiles (x25519,mlkem768,hybrid)")
    fs.StringVar(&impCSV, "impairments", "", "Comma-separated impairments (clean,mtu1300_blackhole,abort_after_ch)")
    fs.IntVar(&headerBudget, "header-budget", 32768, "Header budget bytes")
    fs.StringVar(&outDir, "out", "./reports", "Output directory for artifacts")
    if err := fs.Parse(args); err != nil { return err }
    if target == "" { return errors.New("--target is required") }

    spec := RunSpec{
        Target:            target,
        Profiles:          splitCSV(profilesCSV),
        Impairments:       splitCSV(impCSV),
        HeaderBudgetBytes: headerBudget,
    }

    id := fmt.Sprintf("run-%d", time.Now().Unix())
    res := RunResult{ID: id, Started: time.Now(), Spec: spec}

    // MVP: simulate a run by sleeping briefly
    time.Sleep(500 * time.Millisecond)
    res.Finished = time.Now()
    res.Summary = fmt.Sprintf("profiles=%d impairments=%d target=%s", len(spec.Profiles), len(spec.Impairments), spec.Target)

    // Write artifacts
    if err := writeJSON(filepath.Join(outDir, id, "run.json"), res); err != nil { return err }
    // Minimal text report
    rpt := fmt.Sprintf("PQC Calibrate Report\nID: %s\nTarget: %s\nProfiles: %s\nImpairments: %s\nHeaderBudget: %d\n",
        res.ID, spec.Target, strings.Join(spec.Profiles, ","), strings.Join(spec.Impairments, ","), spec.HeaderBudgetBytes)
    if err := os.WriteFile(filepath.Join(outDir, id, "report.txt"), []byte(rpt), 0o644); err != nil { return err }

    // Render readiness markdown from template skeleton
    if err := renderReadiness(filepath.Join(outDir, id, "readiness.md"), res); err != nil { return err }

    fmt.Println(id)
    return nil
}

func cmdReport(args []string) error {
    fs := flag.NewFlagSet("report", flag.ContinueOnError)
    var id string
    var formats string
    var outDir string
    fs.StringVar(&id, "id", "", "Run ID")
    fs.StringVar(&formats, "format", "json", "Formats (comma-separated): pdf,json")
    fs.StringVar(&outDir, "out", "./reports", "Output directory")
    if err := fs.Parse(args); err != nil { return err }
    if id == "" { return errors.New("--id is required") }

    // MVP: copy/emit existing report.json; PDF not implemented.
    var res RunResult
    b, err := os.ReadFile(filepath.Join(outDir, id, "run.json"))
    if err != nil { return err }
    if err := json.Unmarshal(b, &res); err != nil { return err }

    for _, f := range splitCSV(formats) {
        switch strings.ToLower(f) {
        case "json":
            // already present
        case "pdf":
            // placeholder PDF: write a .pdf.txt note
            note := []byte("PDF generation is not implemented in MVP. Use the JSON or TXT report.")
            if err := os.WriteFile(filepath.Join(outDir, id, "report.pdf.txt"), note, 0o644); err != nil { return err }
        default:
            return fmt.Errorf("unknown format: %s", f)
        }
    }
    fmt.Println("ok")
    return nil
}

func splitCSV(s string) []string {
    if strings.TrimSpace(s) == "" { return nil }
    parts := strings.Split(s, ",")
    out := make([]string, 0, len(parts))
    for _, p := range parts {
        t := strings.TrimSpace(p)
        if t != "" { out = append(out, t) }
    }
    return out
}

// Template rendering (very small helper with functions for join and or)
func renderReadiness(outPath string, res RunResult) error {
    // Load template file
    tplPath := filepath.Join("..", "..", "reports", "templates", "readiness.md.tmpl")
    // Try alternate relative path if running from repo root
    if _, err := os.Stat(tplPath); err != nil {
        tplPath = filepath.Join("pqc-calibrator", "reports", "templates", "readiness.md.tmpl")
    }
    b, err := os.ReadFile(tplPath)
    if err != nil { return err }
    // Very small token replacement for a few fields
    body := string(b)
    repl := map[string]string{
        "{{ .ID }}": res.ID,
        "{{ .Target }}": res.Spec.Target,
        "{{ .Started }}": res.Started.Format(time.RFC3339),
        "{{ .Finished }}": res.Finished.Format(time.RFC3339),
        "{{ join .Profiles \" , \" }}": strings.Join(res.Spec.Profiles, ", "),
        "{{ join .Profiles ", " }}": strings.Join(res.Spec.Profiles, ", "),
        "{{ join .Impairments ", " }}": strings.Join(res.Spec.Impairments, ", "),
        "{{ .HeaderBudget }}": fmt.Sprintf("%d", res.Spec.HeaderBudgetBytes),
    }
    for k, v := range repl { body = strings.ReplaceAll(body, k, v) }
    if err := os.WriteFile(outPath, []byte(body), 0o644); err != nil { return err }
    return nil
}

// Optional minimal REST stub retained for future integration
func serveREST() {
    mux := http.NewServeMux()
    mux.HandleFunc("/run", func(w http.ResponseWriter, r *http.Request){
        w.Header().Set("Content-Type","application/json")
        _ = json.NewEncoder(w).Encode(map[string]any{"accepted": true, "message": "queued"})
    })
    log.Printf("[pqc-calibrate] REST listening on :7070")
    _ = http.ListenAndServe(":7070", mux)
}

func main() {
    if len(os.Args) < 2 {
        fmt.Fprintln(os.Stderr, "usage: pqc-calibrate <run|report|serve>")
        os.Exit(2)
    }
    cmd := os.Args[1]
    var err error
    switch cmd {
    case "run":
        err = cmdRun(os.Args[2:])
    case "report":
        err = cmdReport(os.Args[2:])
    case "serve":
        serveREST()
        return
    default:
        err = fmt.Errorf("unknown command: %s", cmd)
    }
    if err != nil {
        fmt.Fprintln(os.Stderr, "error:", err)
        os.Exit(1)
    }
}
