# Torogo: Pure Go Tor Client & Library

Minimalist, full-featured Tor network client and library implemented **100% in pure Go**, using exclusively the Go standard library (`crypto/*`, `net/*`, `encoding/*`, `compress/zlib`, `io`, `time`). No external dependencies in `go.mod`, zero CGO, and no dependency on the system `tor` binary.

**Torogo** can be imported as a **reusable Go library** (providing standard abstractions like `net.Dialer` and `*http.Client`) or run directly as a **standalone daemon / CLI**, serving as a drop-in replacement for the official C `tor` binary.

---

## Key Features

- **100% Go Standard Library**: Zero external dependencies in `go.mod` / `go.sum`, compiles statically with `CGO_ENABLED=0`.
- **Idiomatic Library API**:
  - `torogo.NewClient(ctx, opts...)` with automatic bootstrap and cached consensus.
  - `client.DialContext(ctx, "tcp", "host:port")` implementing `net.Dialer` returning standard `net.Conn`.
  - `client.HTTPClient()` returning a ready-to-use `*http.Client` with 100% of traffic routed through Tor circuits.
  - `client.Transport()` exposing the underlying `*http.Transport` for custom pooling or timeouts.
- **Drop-in Tor Daemon Replacement**:
  - `client.ListenSOCKS5("127.0.0.1:9050")` runs a local SOCKS5 proxy server. Any application on the operating system (cURL, Firefox, Telegram, Git, Python) can use it identically to the official C `tor` daemon.
  - `client.ListenControl("127.0.0.1:9051")` runs a Tor Control Port server compatible with `control-spec.txt` (`AUTHENTICATE`, `PROTOCOLINFO`, `SIGNAL NEWNYM`, `GETINFO`).
- **Zero DNS Leak**:
  - In `DialContext` and `HTTPClient`, hostnames are **never** resolved locally. The raw domain name is sent inside the encrypted `RELAY_BEGIN` cell directly to the Exit Node, which resolves it remotely on the Tor network.
  - `client.Resolve(ctx, "example.com")` performs remote DNS resolution over Tor using `RELAY_RESOLVE` (`tor-spec.txt §6.4`) without opening a TCP connection.
- **Distroless & Container Ready**: Compiles into a single static binary runnable in minimalist images like `gcr.io/distroless/static-debian12`.
- **Onion Services v3 (.onion)**:
  - Strict validation of v3 `.onion` addresses (56 Base32 characters, SHA3-256 checksum, and version `0x03`).
  - HSDir hash ring indexing, descriptor layer decryption (AES-256-CTR / HMAC-SHA256), and rendezvous cell primitives (`rend-spec-v3.txt`).
- **SENDME Flow Control**:
  - Full flow control window management at circuit level (1000 cells) and stream level (500 cells) per `tor-spec.txt §7.3`.
  - Continuous large-file transfers without stalls or relay disconnects.
- **Persistent Guards on Disk**:
  - Automatically pins primary Guard relays to disk (`~/.torogo/guards.json`), mitigating long-term statistical profiling attacks.
  - Intelligent failure recovery, automatic rotation, and customizable options (`WithGuardFile`, `WithDisableGuards`).
- **Pluggable Transports & SOCKS5 Bridges**:
  - Pure Go RFC 1928 SOCKS5 client dialer to route link connections through local bridge proxies (obfs4, Snowflake, meek).
  - Parser for official Tor Project `Bridge` lines (`Bridge obfs4 IP:Port Fingerprint cert=... iat-mode=...`).
  - Tor PT v2.1 managed subprocess launcher (`TOR_PT_MANAGED_TRANSPORT_VER=1`).
- **Bandwidth-Weighted Path Selection & Family Exclusion**:
  - Weighted random sampling using consensus bandwidth weights (`Wgg`, `Wgd`, `Wmg`, `Wmm`, `Wee`, `Wed`).
  - Enforces subnet `/16` isolation and node family exclusion (`sameFamily`) across all circuit hops.
- **Traffic Padding Keep-Alive**:
  - Generates and handles `CmdPadding` cells per `padding-spec.txt` to keep idle circuits alive through NAT and firewall boundaries.

---

## Installation

```bash
go get github.com/pedromol/torogo
```

---

## Library Usage

### 1. HTTP Requests with `*http.Client`

```go
package main

import (
	"context"
	"fmt"
	"io"
	"log"

	"github.com/pedromol/torogo"
)

func main() {
	ctx := context.Background()

	// Initialize Tor client (downloads and validates consensus)
	client, err := torogo.NewClient(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	// Standard Go *http.Client routed through Tor
	httpClient := client.HTTPClient()

	resp, err := httpClient.Get("https://check.torproject.org/api/ip")
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	fmt.Println(string(body))
	// Output: {"IsTor":true,"IP":"..."}
}
```

### 2. Generic TCP Streams with `DialContext` (`net.Conn`)

```go
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/pedromol/torogo"
)

func main() {
	ctx := context.Background()

	client, err := torogo.NewClient(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	// Connects to any TCP endpoint through a 3-hop Tor circuit
	conn, err := client.DialContext(ctx, "tcp", "check.torproject.org:443")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	fmt.Println("Connected securely via Tor circuit!", conn.RemoteAddr())
}
```

### 3. Local SOCKS5 Proxy Daemon (Drop-in Replacement for C `tor`)

Run a local SOCKS5 proxy server on port 9050. Any external tool (cURL, Firefox, Telegram, Git, Python scripts) can route its traffic through Tor without needing the C `tor` package installed:

```go
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/pedromol/torogo"
)

func main() {
	client, err := torogo.NewClient(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	// Listen on default Tor SOCKS5 port 9050
	server, err := client.ListenSOCKS5("127.0.0.1:9050")
	if err != nil {
		log.Fatal(err)
	}
	defer server.Close()

	fmt.Println("Torogo SOCKS5 proxy running on", server.Addr())
	select {} // Keep server running
}
```

In your terminal:
```bash
curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip
```

### 4. Remote DNS Resolution (Zero Local Leak)

Resolve any domain name remotely at the Exit Node without opening a TCP connection:

```go
ips, err := client.Resolve(ctx, "duckduckgo.com")
if err != nil {
	log.Fatal(err)
}
fmt.Println("Remote Tor resolved IPs:", ips)
```

---

## Standalone CLI Usage

Torogo includes a full CLI binary:

```bash
# Build binary
go build -o torogo ./cmd/torogo

# 1. Run quick connectivity verification
./torogo

# 2. Start as a background Tor daemon (SOCKS5 + Control Port)
./torogo -socks 127.0.0.1:9050 -control 127.0.0.1:9051

# 3. Resolve hostnames remotely via Tor
./torogo -resolve duckduckgo.com
```

---

## Project Structure

```
torogo/
├── client.go                 # Primary public library API (Client, DialContext, HTTPClient, Resolve)
├── client_test.go            # Public API unit tests
├── socks_server.go           # Local SOCKS5 proxy server daemon (RFC 1928)
├── socks_server_test.go      # SOCKS5 proxy server unit tests
├── control_server.go         # Tor Control Port server (control-spec.txt)
├── control_server_test.go    # Control Port unit tests
├── cmd/
│   └── torogo/
│       └── main.go           # Standalone CLI and Tor daemon executable
├── internal/
│   └── tor/
│       ├── cell.go           # Fixed (509B) and variable cell framing
│       ├── cell_test.go      # Cell encoding and padding tests
│       ├── certs.go          # RSA authority certs and Ed25519 cert parsers
│       ├── circuit.go        # Circuit lifecycle, onion wrapping, SENDME flow control, and remote resolve
│       ├── consensus.go      # Directory Authorities, microdesc consensus parsing, signatures, bandwidth weights
│       ├── crypto.go         # ntor handshake (Curve25519/X25519, HKDF-SHA256, HMAC-SHA256)
│       ├── directory.go      # Directory client, microdescriptor fetcher, bandwidth-weighted path selection
│       ├── directory_test.go # Authority tests, bandwidth weighting, and family exclusion tests
│       ├── embedded_certs.go # Embedded fallback authority certificates
│       ├── flow_control_test.go # Circuit and stream SENDME window tests
│       ├── guards.go         # Persistent Guard nodes on disk (~/.torogo/guards.json)
│       ├── guards_test.go    # Guard persistence and selection tests
│       ├── link.go           # TLS link connection and link handshake (v4/v5)
│       ├── ntor_test.go      # ntor v3 handshake unit tests
│       ├── onion.go          # Onion v3 address decoding, SHA3-256 checksum, HSDir ring, descriptor decryption
│       ├── onion_test.go     # Onion address, checksum, and descriptor crypto tests
│       ├── pt.go             # Pluggable Transports client, SOCKS5 client dialer, and bridge parsing
│       ├── pt_test.go        # Bridge lines and SOCKS5 client dialer tests
│       ├── resolve_test.go   # Remote RELAY_RESOLVE parser tests
│       └── stream.go         # Stream multiplexer over Tor circuits (net.Conn)
├── docs/
│   ├── ARCHITECTURE.md       # Comprehensive architectural and protocol documentation
│   └── plans/
│       └── pure-go-tor-plan.md # Original engineering design specification
├── Dockerfile                # Multi-stage build for static distroless container
└── go.mod                    # Pure Go module (zero external dependencies)
```

---

## Requirements

- Go 1.24 or higher (tested with Go 1.27).
- Internet access to connect to official Directory Authorities and Tor relays.

---

## License

MIT License. See [LICENSE](LICENSE) for details.
