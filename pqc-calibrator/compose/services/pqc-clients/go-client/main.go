package main

import (
    "crypto/tls"
    "fmt"
    "io"
    "log"
    "net/http"
    "os"
    "time"
)

func main() {
    target := os.Getenv("TARGET_URL")
    if target == "" { target = "http://pqc-go-server:8443/hello" }

    // NOTE: This client is HTTP for MVP; keeping TLS transport in place for later upgrades.
    tr := &http.Transport{ TLSClientConfig: &tls.Config{ InsecureSkipVerify: true } }
    c := &http.Client{ Transport: tr, Timeout: 10 * time.Second }

    resp, err := c.Get(target)
    if err != nil {
        log.Fatalf("request failed: %v", err)
    }
    defer resp.Body.Close()
    b, _ := io.ReadAll(resp.Body)
    fmt.Printf("status=%d body=%s\n", resp.StatusCode, string(b))
}
