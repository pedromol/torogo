# AGENTS.md — Torogo Project Guidelines for AI Agents

This document contains technical context, constraints, and essential guidelines for AI agents maintaining or evolving this repository.

---

## 1. Overview and Core Principles

**Torogo** is a pure Go implementation of a Tor network client built from scratch.
The following principles **must never** be violated:

1. **Zero External Dependencies (R1 & R2)**:
   - The project uses **exclusively** Go standard library packages (`crypto/*`, `net/*`, `encoding/*`, `compress/zlib`, `io`, `time`, etc.).
   - Do not add external dependencies to `go.mod` (`go get` must not be used for third-party libraries).
   - Do not use CGO (`CGO_ENABLED=0`).
   - Do not depend on external operating system binaries (such as the C `tor` binary).
2. **Static Binary & Distroless (R3)**:
   - Binaries must compile statically and run in minimalist containers like `gcr.io/distroless/static-debian12`.
3. **Tor Specification Fidelity**:
   - All wire-spec behavior must strictly follow official Tor specifications: `tor-spec.txt`, `dir-spec.txt`, `cert-spec.txt`, `rend-spec-v3.txt`, `path-spec.txt`, `padding-spec.txt`, and `control-spec.txt`.

---

## 2. Architecture Map

- `client.go` (root, `package torogo`):
  - Primary public library API (`Client`, `DialContext`, `Dial`, `Transport`, `HTTPClient`, `Resolve`).
  - Thread-safe consensus cache (`getConsensus`) validated against validity windows (`sync.RWMutex`).
  - Stream/circuit encapsulation (`torConn`) for automatic cleanup on `net.Conn.Close()`.

- `socks_server.go`:
  - RFC 1928 SOCKS5 proxy server daemon (`client.ListenSOCKS5`).
  - Serves as a drop-in replacement for the official C `tor` daemon on port `9050` with zero local DNS leakage.

- `control_server.go`:
  - Tor Control Port server (`control-spec.txt`, `client.ListenControl`).
  - Listens on port `9051` handling `AUTHENTICATE`, `PROTOCOLINFO`, `SIGNAL NEWNYM`, `GETINFO`, and `SETEVENTS`.

- `cmd/torogo/main.go`:
  - CLI application and integration tester.
  - Supports daemon mode (`-socks 127.0.0.1:9050 -control 127.0.0.1:9051`), remote DNS lookup (`-resolve <host>`), and live connectivity check.

- `internal/tor/`:
  - `cell.go`: Fixed (509 bytes) and variable cells. Commands `VERSIONS`, `CERTS`, `NETINFO`, `CREATE2`, `CREATED2`, `RELAY`, `RELAY_EARLY`, `PADDING`.
  - `link.go`: TLS link over relay ORPort. Handshake v4/v5 (`VERSIONS` → `CERTS` → `AUTH_CHALLENGE` → `NETINFO`).
  - `circuit.go`: Circuit creation (`NewCircuit`, `Extend`), onion wrapping layers, SENDME flow control, and remote DNS resolve (`RELAY_RESOLVE`).
  - `crypto.go`: **ntor** handshake (Curve25519/X25519, HKDF-SHA256, HMAC-SHA256) and raw RSA PKCS#1 v1.5 verification.
  - `consensus.go`: Consensus data structures, Directory Authorities, microdescriptor parsing, authority signature quorum, and bandwidth weights.
  - `directory.go`: HTTP fetching of consensus and microdescriptors (`/tor/micro/d/...`), bandwidth-weighted path selection, and family exclusion (`SelectPathWithGuards`).
  - `certs.go`: RSA authority certificates (`dir-key-certificate-version 3`) and Ed25519 certificates (types 4 and 5).
  - `stream.go`: `net.Conn` stream multiplexer over relay cells (`RELAY_BEGIN`, `RELAY_DATA`, `RELAY_CONNECTED`, `RELAY_END`, `RELAY_BEGIN_DIR`).
  - `guards.go`: Persistent disk storage for Guard nodes (`~/.torogo/guards.json`), failure tracking, and automatic rotation.
  - `onion.go`: Onion v3 address decoding/validation (SHA3-256 checksum), HSDir hash ring calculation, descriptor layer decryption (AES-256-CTR/HMAC-SHA256), and rendezvous primitives.
  - `pt.go`: Pluggable Transports client, pure Go SOCKS5 client dialer, bridge line parsing, and Tor PT v2.1 managed process runner.

---

## 3. Protocol Peculiarities & Pitfalls

When modifying or extending the code, adhere to these critical specification details:

### Consensus & Signatures (`dir-spec.txt`)
- **Signed Range:** Signed text begins at the start of `network-status-version` and ends immediately after the first `directory-signature ` space (inclusive).
- **`directory-signature` line:** Format is `directory-signature [algorithm] <identity-digest> <signing-key-digest>`. The cryptographic signature is in the subsequent PEM block (`-----BEGIN SIGNATURE-----`).
- **Microdescriptors:** URL path `/tor/micro/d/<digest>` uses **unpadded** Base64 (`base64.RawStdEncoding`). Using padding `=` causes HTTP 404 errors on directory caches.

### NETINFO Cell (`tor-spec.txt §4.5`)
- Payload structure:
  - `Timestamp` [4 bytes]
  - `OTHERADDR`: `ATYPE` [1 byte: 0x04 for IPv4], `ALEN` [1 byte: 4], `AVAL` [4 bytes]
  - `NMYADDR` [1 byte: 0x00 if undisclosed]
- Never send `ATYPE = 0`, as relays immediately close the connection.

### CREATED2 Cell (`tor-spec.txt §5.1`)
- Unlike `CREATE2` (which starts with a 2-byte `HTYPE`), `CREATED2` does **not** include `HTYPE`.
- The payload starts directly with `HLEN` (2 bytes, big-endian) followed by `HDATA` (`HLEN` bytes).

### Remote DNS & Zero Leakage (`tor-spec.txt §6.2 / §6.4`)
- Hostnames are sent as raw strings inside `RELAY_BEGIN` or `RELAY_RESOLVE` cells.
- The local host must never call `net.LookupIP` or OS resolvers; all DNS resolution occurs remotely at the Exit Node.

---

## 4. Development & Testing Guidelines

- **Unit Tests**: Always run `go test -v ./...` before concluding changes.
- **Live Integration Testing**: To verify health against the live Tor network:
  ```bash
  go run ./cmd/torogo
  ```
  The command should output `circuit established` and `IsTor=true` with an external exit IP.
- **Formatting and Linting**: Adhere strictly to idiomatic Go standards (`gofmt` / `go vet`).
