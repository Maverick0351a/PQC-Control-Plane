package main

// SNDT Notary bootstrap: placeholder service that could sign/notarize controller decisions.
// Exposes /__health and /notary/info for integration tests (future expansion).

import (
  "encoding/json"
  "log"
  "net/http"
  "os"
)

func main(){
  port := os.Getenv("SNDT_PORT"); if port == "" { port = "8090" }
  mux := http.NewServeMux()
  mux.HandleFunc("/__health", func(w http.ResponseWriter, r *http.Request){ w.Header().Set("Content-Type","application/json"); w.Write([]byte(`{"status":"ok"}`)) })
  mux.HandleFunc("/notary/info", func(w http.ResponseWriter, r *http.Request){
    info := map[string]any{"service":"sndt","version":"v0","signing":"placeholder"}
    w.Header().Set("Content-Type","application/json")
    _ = json.NewEncoder(w).Encode(info)
  })
  log.Printf("[sndt] listening on :%s", port)
  if err := http.ListenAndServe(":"+port, mux); err != nil { log.Fatal(err) }
}
