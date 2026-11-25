---
title: Pure Go Tor Client - Plan
type: feat
date: 2026-11-05
artifact_contract: ce-unified-plan/v1
execution: code
---

## Goal Capsule

Objective: A Go application using only the standard library (no third-party libs, no OS binaries) that connects to the Tor network, builds a full 3-hop circuit (guard → middle → exit), performs an HTTPS GET to https://check.torproject.org/ through the exit node, and prints a verdict ("está usando Tor: sim/não") plus the observed exit IP. The binary must be buildable as a distroless `static` image with `CGO_ENABLED=0`. Means: implement the Tor protocol from scratch in pure Go (link handshake v3, ntor, cell crypto, directory bootstrap). Stop conditions: the binary runs successfully in a distroless container and prints the expected verdict + exit IP. Authority hierarchy: user-directed decisions on strategy (pure-Go vs embedded binary), circuit length (3 hops), embedded data (authority keys + CA bundle), output format (verdict + IP). Users who cannot satisfy the hard requirements may not realize the scale; plan explicitly documents the fork.

## Product Contract

### Summary
Implement a minimal Tor client in Go using only `crypto/*`, `net/*`, `encoding/base64`, `compress/zlib` — all stdlib — to build a 3-hop circuit and fetch an HTTPS resource. Output a legible Tor-detection verdict and exit IP. Must not depend on external binaries (`tor`) or third-party packages. Must produce a static Go binary that runs in `gcr.io/distroless/static-debian12` without network binaries.

### Problem Frame
Tor anonymity requires routing TCP streams through at least 3 relays. The Tor protocol is openly specified (tor-spec, dir-spec, control-spec). Implementing a client from scratch in Go is feasible given Go 1.27's stdlib crypto (X25519, ed25519, HKDF-SHA256, AES-CTR, SHA-1). The main challenge is the wire-level protocol (cell format, link handshake, ntor key derivation, relay crypto, directory consensus parsing) and trust without CA infrastructure in distroless.

### Requirements
- **R1.** 100% Go stdlib — no `go get`, no CGO, no external .so/.dll, no `tor` binary.
- **R2.** No third-party dependencies in `go.mod` or `go.sum` beyond `module` line.
- **R3.** Binary builds as `CGO_ENABLED=0` and runs in `gcr.io/distroless/static-debian12` (no shell, no extra binaries).
- **R4.** Circuit must be a full 3-hop path (guard → middle → exit) using ntor key handshakes.
- **R8.** The handshake must use **ntor-v3** (the modern ntor key format; ntorv3 is the successor to ntor and is what current relays accept for CREATE2), verifying the v3 handshake payload format and keys per the ntorv3 spec.
- **R5.** HTTPS GET to `https://check.torproject.org/` must traverse the Tor exit; result printed to stdout as `"IsTor: true <exit-ip>"` or `"IsTor: false"`.
- **R6.** Directory bootstrap authenticates consensus/microdescriptors against embedded authority ed25519 public keys; TLS to authorities uses `InsecureSkipVerify` + signature validation.
- **R7.** Output must include Tor‑detection verdict and the observed exit IP address.

### Acceptance Examples
- `./torclient` → prints `"circuit established\nIsTor=true IP=203.0.113.42"` (example exit IP)
- `docker run --rm my-tor-image` → same output, no shell access
- Binary size under 10 MB static

### Scope Boundaries
- In-scope: pure-Go Tor client, 3-hop circuit, directory bootstrap, HTTPS GET via exit, verdict+IP output, Dockerfile for distroless.
- Out-of-scope: SOCKS proxy, multiple concurrent streams, circuit reconnection/rotation, onion services, any use of the `tor` system binary, pluggable transports.

## Planning Contract

### Key Technical Decisions
- **KTD1.** Pure-Go Tor client vs. embedding a static `tor` binary — user-directed (selected pure-Go to satisfy R1-R3). Cites: requirements R1-R3.
- **KTD6.** ntor-v3 handshake vs. original ntor — user-directed via requirement R8 (selected ntor-v3 per current relay acceptance). Cites: requirements R4, R8.
- **KTD2.** 3-hop circuit vs. single-hop exit — user-directed (selected 3 hops for real Tor behavior; single-hop likely rejected by exits). Cites: requirements R4.
- **KTD3.** Embedded data blobs (authority ed25519 keys + CA bundle) vs. runtime DNS/CA — user-directed (selected embedded to satisfy R6 without OS binaries). Cites: requirements R6.
- **KTD4.** Verdict+IP output vs. raw HTTP status+body — user-directed (selected clean verdict per requirements R5). Cites: requirements R5.
- **KTD5.** Distroless static Dockerfile vs. no container deliverable — user-directed (selected per requirements R3). Cites: requirements R3.

### Assumptions
- Go 1.27.0 stdlib provides all needed crypto: `crypto/ecdh` (X25519), `crypto/ed25519`, `crypto/hkdf` (Go 1.24+), `crypto/sha256`, `crypto/sha1`, `crypto/aes`, `crypto/cipher`, `crypto/rand`, `crypto/tls`.
- Directory authority lists and consensus format are stable for the foreseeable period; embedded keys will need periodic update but are within plan control.
- check.torproject.org returns a deterministic page body that includes a Tor‑detection statement and the client's exit IP (it does: "Congratulations. This browser is configured to use Tor." and displays IP).
- The pure-Go resolver (`netgo`) suffices for the Tor exit's DNS; the exit resolves the destination, so the client does not need local DNS for the destination.

### Open Questions (none at this depth)
- (none)

## Implementation Units

### U1. Tor cell framing and link handshake v3
- **Files:** `tor/cells.go`, `tor/linkhandshake.go`
- **Approach:** Encode/decode Tor cells: 4-byte circuit ID + 1-byte command + variable-length payload. Fixed commands: VERSIONS (3), CERTS (129), AUTH_CHALLENGE (130), NETINFO (8). Variable commands have length prefix. Implement link handshake: send NETINFO after receiving VERSIONS+CERTS+AUTH_CHALLENGE from guard; validate CERTS against guard's ed25519 identity from microdescriptor.
- **Test scenarios:** 
  - Parse a valid VERSIONS cell payload with commands `[3,4]` or `[4,5]`.
  - Parse a CERTS cell and extract the relay's ed25519 identity key.
  - Build and send a NETINFO cell with timestamp; verify server echoes it.
- **Verification:** `go test ./tor/... -run TestCellEncoding` passes.

### U2. ntor handshake (CREATE2/CREATED2)
- **Files:** `tor/ntor.go`
- **Approach:** Implement the **ntor-v3** handshake (per ntorv3 spec). Use Curve25519 X25519 shared secret via `crypto/ecdh` and derive ntor-v3 keys using HKDF-SHA256 (`crypto/hkdf`) with the ntorv3-specific salt and info strings. Compute the HMAC-SHA256 confirmation. Build CREATE2 cell with the ntorv3 handshake payload; on CREATED2, derive forward/backward cipher keys and SHA-1 running digests for relay cells. The ntor-v3 design does not possess-proof the shared secret; Go's `ecdh.X25519().SharedSecret(peer)` returns raw 32-byte secret matching Tor's design. The CREATE2 payload uses the ntorv3 command byte and the v3 handshake structure (client ephemeral key + relay ephemeral key + encrypted relay handshake), not the legacy ntor format.
- **Test scenarios:** 
  - Derive the same ntor-v3 secret two ways (client and guard) and verify length 32.
  - Sign and verify an ntor-v3 confirmation HMAC.
  - Encode/decode a CREATE2 cell payload using the ntorv3 format and verify CREATED2 round-trip with a mock guard key.
  - Reject a CREATE2 payload that does not match the ntorv3 format (e.g., legacy ntor or malformed).
- **Verification:** `go test ./tor/... -run TestNtorV3` passes.

### U3. Relay cell crypto (AES-128-CTR + SHA-1 digests)
- **Files:** `tor/relaycrypto.go`
- **Approach:** Each hop derives forward and backward cipher keys and SHA-1 digests from the ntor output. Relay cells have a 5-byte header (command + recognized + stream ID + 3-byte digest + 2-byte length) and a 509-byte payload encrypted with AES-128-CTR using the hop's forward key; the digest accumulates over all cells in each direction per hop. Implement the onion-wrapping: cell for hop N is encrypted with hop N's keys, then the result is the plaintext for hop N-1, etc. RELAY cells crossing the full circuit are encrypted layer-onion style.
- **Test scenarios:** 
  - Given known ntor output, derive correct cipher keys and match test vectors from Tor's test suite (available in tor source).
  - Encode a RELAY cell with a known plaintext and verify decryption with matched keys.
  - Verify that digest updates produce the expected running-SHA-1 value after N cells.
- **Verification:** `go test ./tor/... -run TestRelayCrypto` passes.

### U4. EXTEND2 for multi-hop circuits
- **Files:** `tor/extend.go`
- **Approach:** ENCODE EXTEND2 cell: payload contains link specifier (IPv4 address + 2-byte port + relay's ed25519 identity + RSA identity) followed by ntor handshake for the next hop. On the client side, CREATE2 to guard, then EXTEND2 to middle, then EXTEND2 to exit. Each EXTEND2 is processed by the receiving relay, which validates the link specifier, performs its own ntor handshake, and forwards the extended circuit. Client waits for CREATED cells after each EXTEND2.
- **Test scenarios:** 
  - Encode an EXTEND2 cell with a known middle relay's link specifiers and ntor key; decode and verify layout.
  - Simulate the three EXTEND2 steps and verify CREATED2 cells are produced in order.
- **Verification:** `go test ./tor/... -run TestExtend` passes.

### U5. Directory bootstrap (consensus + microdescriptors)
- **Files:** `tor/dir/bootstrap.go`
- **Approach:** Embed a small list of 3 directory authority IPv4:port constants (authority data from current consensus). Fetch consensus from an authority over TLS with `InsecureSkipVerify`; verify the consensus signature against the embedded authority ed25519 identity key + `rsa.VerifyPKCS1v15(signingKey, crypto.Hash(0), digest, sig)` pattern (per live verification: digest is `sha1.Sum` of the signed prefix ending at the space after `directory-signature`). Parse consensus to extract: flag `r` lines (guard/middle/exit), `p` lines (exit policy), `r` identity base64 (unpadded 27 chars), `m` microdescriptor sha256 digests (43 unpadded chars). Then fetch microdescriptors from `/tor/micro/all` (or per-authority URLs); verify each microdescriptor's sha256 matches the consensus `m` line. Store relays' IPv4/port, ntor onion key, and ed25519 identity key.
- **Test scenarios:** 
  - Fetch a live consensus from a known authority, verify signatures with embedded keys.
  - Parse the `r` and `m` fields from a consensus excerpt.
  - Decode a microdescriptor and verify its sha256 against the consensus `m` line.
- **Verification:** `go test ./tor/dir/... -run TestBootstrap` passes.

### U6. Stream setup: RELAY_BEGIN/DATA/END and end-to-end TLS
- **Files:** `tor/stream.go`, `tor/main.go`
- **Approach:** After circuit is built (3 EXTEND2 + CREATED2), send RELAY_BEGIN cell with target host/port (`check.torproject.org:443`) and stream ID 1. Receive RELAY_CONNECTED. Then write an HTTP/1.1 GET request directly over the tunnel (no `net/http` wrapper; manually construct `GET / HTTP/1.1\r\nHost: check.torproject.org\r\n\r\n` followed by the response). Parse the response body for the Tor‑detection verdict line and the exit IP display. The exit IP appears in the page body (check.torproject.org shows "Your IP address is ...").
- **Test scenarios:** 
  - Given a mock circuit with pre-derived relay crypto state, send RELAY_BEGIN and verify RELAY_CONNECTED.
  - Parse the HTTP response body and extract the Tor‑detection sentence and IP.
  - Print the formatted output `"está usando Tor: sim <ip>"` or `"está usando Tor: não"`.
- **Verification:** Integration test with a minimal mock Tor circuit confirms output format.

### U7. Dockerfile for distroless static
- **Files:** `Dockerfile`
- **Approach:** Multi-stage build: first stage `FROM golang:1.27-stretch AS builder` with `WORKDIR /app`, `COPY go.mod go.sum .`, `RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -installsuffix static -ldflags "-s -w" -o torclient .`, then `FROM gcr.io/distroless/static-debian12 AS runtime` with `COPY --from=builder /app/torclient /torclient`. No `tzdata`, no `ca-certificates` (embedded CA bundle used for Tor, not for destination; check.torproject.org TLS will use the embedded CA bundle or `InsecureSkipVerify`; the binary uses `crypto/tls` with a custom `RootCAs` pool from embedded PEM). Entry point `/torclient`. Build: `docker build -t my-tor-image .`
- **Test scenarios:** 
  - `docker build` succeeds without errors.
  - `docker run --rm my-tor-image` prints the expected verdict + IP (if Tor network reachable; in offline CI, test the binary's path logic).
- **Verification:** `docker build` and `docker run` exit 0; output matches format.

## Verification Contract

- **Unit tests:** `go test ./...` covers cell encoding, ntor key derivation, relay crypto, extend cells, directory bootstrap parsing. Target >80% branch coverage on protocol parsers.
- **Build verification:** `CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /dev/null .` exits 0.
- **Distroless build verification:** `docker build -t torclient .` and `docker run --rm torclient` prints help/exits cleanly (no network needed for unit tests; integration needs network).
- **Output format verification:** Binary stdout matches regex `está usando Tor: (sim|não) ` followed by optional IP.
- **No external deps verification:** `go mod verify` reports no unknown revisions; `go list -m all` lists only the module itself.

## Definition of Done

- **Global:** All Implementation Units U1‑U7 are coded, unit‑tested, and pass. The Dockerfile builds a static distroless image. The binary, when run outside Tor (no network), prints the correct verdict format for the offline code path (empty circuit, no exit IP → `"está usando Tor: não"`).
- **Per‑unit:** Each U1‑U7 has at least one unit test passing in isolation; each U's `Approach` matches the plan's KTD‑justified design; each U's `Files` are the only files the unit touches.
- **Code quality:** `go vet ./...` passes; no unused imports; all error returns checked; all exported symbols documented with godoc‑style comments.
- **Cleanup:** No temporary test artifacts committed; `go.sum` contains exactly the module's own entry; `docker build` produces an image with no more than the binary and minimal libc (distroless static). Abandoned approach code (e.g., early drafts of ntor) is removed before final commit.
- **Verification evidence:** Commit `torclient` includes a `verification/` subdirectory with test vector files and a short `README.md` describing how each test maps to a unit in the plan. The plan artifact's `Appendix` cites the research URLs that shaped each KTD.

## Appendix

### Research breadcrumbs
- Tor specification: `tor-spec.txt` (cells, link handshake, ntor, relay crypto) — https://git.torproject.org/torspec/tor-spec.git
- Directory protocol: `dir-spec.txt` — https://git.torproject.org/torspec/dir-spec.git
- ntor proposal: `NTOR` proposal 251 — https://git.torproject.org/ proposals/ntor.git
- Go 1.27 crypto changes: https://go.dev/doc/go1.27
- Distroless static README: https://github.com/GoogleContainerTools/distroless
- Live consensus signature verification pattern (sha1 digest prefix): verified against moria1 consensus on 2026-11-05 — see research subagent output.

### Prior art (reference only, not dependency)
- `github.com/eyedeekay/onramp` — I2P pure‑Go implementation; cell‑format ideas adaptable.
- `github.com/ProtonMail/go-crypto` — collection of stdlib‑only crypto primitives; useful for HKDF/SHA1 patterns.
- `git.torproject.org/torspec/` — authoritative source for all wire‑level definitions; primary reference for implementation.

---

## Status da Implementação e Evolução para Biblioteca (Novembro/2026)

Todas as unidades planejadas (U1 a U7) foram concluídas, testadas e validadas contra a rede Tor viva. Além do CLI executável e da imagem distroless original, o projeto foi expandido para ser uma **biblioteca Go exportável**:

1. **U1 a U7 Concluídos:**
   - Link handshake v4/v5 e validação de certificados Ed25519 (U1).
   - Handshake modern ntor v3 com X25519 e HKDF-SHA256 (U2).
   - Criptografia de células em camadas AES-128-CTR com digest contínuo SHA-1 (U3).
   - Construção de circuitos multi-hop via CREATE2 e EXTEND2 (U4).
   - Bootstrap de diretório contra autoridades reais e validação de assinaturas de consenso RSA-SHA256 (U5).
   - Multiplexação de streams TCP sobre circuitos e conexão HTTPS ponta a ponta (U6).
   - Dockerfile multi-stage estático para imagem distroless (U7).

2. **Evolução para Biblioteca (`package torogo`):**
   - Criado pacote público na raiz com `torogo.Client`, `DialContext` (`net.Dialer`), `HTTPClient` e `Transport`.
   - Adicionado cache de consenso thread-safe em memória.
   - Suporte a seleção de caminho para portas arbitrárias (`SelectPathForPort`).
