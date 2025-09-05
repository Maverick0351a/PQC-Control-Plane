package main

import (
    "bufio"
    "encoding/hex"
    "encoding/json"
    "flag"
    "fmt"
    "io"
    "os"

    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    "github.com/google/gopacket/pcap"

    "pathlab"
)

type result struct {
    TotalLen       int      `json:"total_len"`
    Groups         []uint16 `json:"groups"`
    HasKyberHybrid bool     `json:"has_kyber_hybrid"`
}

func parseBuffer(buf []byte) (*result, error) {
    total, groups, has, err := pathlab.ParseClientHello(buf)
    if err != nil {
        return nil, err
    }
    return &result{TotalLen: total, Groups: groups, HasKyberHybrid: has}, nil
}

func readAll(r io.Reader) ([]byte, error) {
    b := bufio.NewReader(r)
    return io.ReadAll(b)
}

func parseFromHexOrRaw(path string, isHex bool) (*result, error) {
    var data []byte
    var err error
    if path == "-" || path == "" {
        data, err = readAll(os.Stdin)
    } else {
        f, e := os.Open(path)
        if e != nil { return nil, e }
        defer f.Close()
        data, err = readAll(f)
    }
    if err != nil { return nil, err }
    if isHex {
        // strip whitespace
        compact := make([]byte, 0, len(data))
        for _, c := range data {
            if c == ' ' || c == '\n' || c == '\r' || c == '\t' { continue }
            compact = append(compact, c)
        }
        dec := make([]byte, hex.DecodedLen(len(compact)))
        n, err := hex.Decode(dec, compact)
        if err != nil { return nil, err }
        data = dec[:n]
    }
    return parseBuffer(data)
}

func parseFromPCAP(path string, port uint, limit int) (*result, error) {
    handle, err := pcap.OpenOffline(path)
    if err != nil { return nil, err }
    defer handle.Close()

    src := gopacket.NewPacketSource(handle, handle.LinkType())
    buf := make([]byte, 0, 4096)
    found := false
    for pkt := range src.Packets() {
        if limit > 0 { limit--; if limit == 0 { break } }
        tcpL := pkt.Layer(layers.LayerTypeTCP)
        if tcpL == nil { continue }
        tcp := tcpL.(*layers.TCP)
        // Filter port if provided
        if port != 0 {
            if uint(tcp.SrcPort) != port && uint(tcp.DstPort) != port { continue }
        }
        if len(tcp.Payload) == 0 { continue }
        buf = append(buf, tcp.Payload...)
        if len(buf) >= 9 && buf[0] == 0x16 { // handshake content type and header present
            if res, err := parseBuffer(buf); err == nil {
                return res, nil
            }
            // else keep buffering until complete
            found = true
        }
    }
    if found {
        return nil, fmt.Errorf("incomplete handshake in pcap (need more packets)")
    }
    return nil, fmt.Errorf("no TLS ClientHello found")
}

func main() {
    in := flag.String("in", "", "Input file path ('-' for stdin); if empty, reads stdin")
    isHex := flag.Bool("hex", false, "Treat input as hex string (whitespace allowed)")
    pcapPath := flag.String("pcap", "", "Parse from a PCAP file instead of raw/hex input")
    port := flag.Uint("port", 443, "TCP port filter for pcap parsing (0 to disable)")
    limit := flag.Int("limit", 0, "Max packets to scan from pcap (0 = no limit)")
    asJSON := flag.Bool("json", true, "Output JSON (default true)")
    flag.Parse()

    var (
        res *result
        err error
    )
    if *pcapPath != "" {
        res, err = parseFromPCAP(*pcapPath, *port, *limit)
    } else {
        res, err = parseFromHexOrRaw(*in, *isHex)
    }
    if err != nil {
        fmt.Fprintln(os.Stderr, "error:", err)
        os.Exit(1)
    }
    if *asJSON {
        enc := json.NewEncoder(os.Stdout)
        enc.SetIndent("", "  ")
        _ = enc.Encode(res)
    } else {
        fmt.Printf("total_len=%d groups=%v has_kyber_hybrid=%v\n", res.TotalLen, res.Groups, res.HasKyberHybrid)
    }
}
