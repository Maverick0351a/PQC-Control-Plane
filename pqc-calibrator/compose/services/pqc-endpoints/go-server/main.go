package main

import (
    "fmt"
    "log"
    "net/http"
    "os"
)

func main() {
    // NOTE: This is HTTP-only MVP. Replace with TLS server supporting PQC groups.
    groups := os.Getenv("TLS_GROUPS")
    mux := http.NewServeMux()
    mux.HandleFunc("/__health", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
    mux.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        w.Write([]byte(fmt.Sprintf(`{"msg":"hello pqc","tls_groups":"%s"}`, groups)))
    })

    addr := ":8443"
    log.Printf("[pqc-go-server] listening on %s (HTTP MVP) TLS_GROUPS=%s", addr, groups)
    log.Fatal(http.ListenAndServe(addr, mux))
}
