# Torogo Architecture

This document describes the internal architecture of **Torogo**, a pure Go implementation of the Tor network client protocol built without external dependencies or CGO.

---

## 1. Layered Architecture Overview

```
+-------------------------------------------------------------------+
|                           Application                             |
|          (cmd/torogo or external project using the library)       |
+---------------------------------+---------------------------------+
|          *http.Client           |        client.DialContext       |
|    (http.Transport with Tor)    |         (net.Conn / TCP)        |
+---------------------------------+---------------------------------+
|                       torogo.Client (client.go)                   |
|     (Consensus Cache, Circuit Pooling, Safe Lifecycle Management) |
+-------------------------------------------------------------------+
|               Local Proxy Daemons (SOCKS5 & Control)              |
|        (socks_server.go :9050, control_server.go :9051)           |
+-------------------------------------------------------------------+
|                     Stream Layer (stream.go)                      |
|     (TCP Multiplexing, RELAY_BEGIN / RELAY_DATA / RELAY_END)      |
+-------------------------------------------------------------------+
|                    Circuit Layer (circuit.go)                     |
|      (Onion Wrapping AES-128-CTR, SHA-1 Digest, CREATE2/EXTEND2)  |
+-------------------------------------------------------------------+
|                     ntor Handshake (crypto.go)                    |
|       (Curve25519 / X25519, HKDF-SHA256, HMAC-SHA256 Auth)        |
+-------------------------------------------------------------------+
|                     TLS Link & Cells (link.go, cell.go)           |
|        (Link Protocol 4/5, VERSIONS, CERTS, NETINFO, 509B Cells)  |
+-------------------------------------------------------------------+
|                     Directory & Consensus (directory.go)          |
|        (Microdesc Consensus Bootstrap, RSA-SHA256 Signatures)     |
+-------------------------------------------------------------------+
```

---

## 2. Components & Protocol Lifecycle

### 2.1. Directory Bootstrap and Consensus (`consensus.go`, `directory.go`)
1. **Consensus Download:** The client queries one of the 10 official Directory Authorities via HTTP (`/tor/status-vote/current/consensus-microdesc`).
2. **Signature Verification:**
   - The signed range spans from the start of `network-status-version` to the space immediately following the first `directory-signature ` line (inclusive).
   - The SHA-256 digest of this range is verified against the RSA PKCS#1 v1.5 signature extracted from each authority's PEM block.
   - The consensus is accepted only when a valid quorum of recognized authority signatures is present (`N/2 + 1`).
3. **Microdescriptor Fetching:**
   - Candidate router microdescriptor digests are retrieved via `/tor/micro/d/<digest>` using unpadded Base64.
   - The microdescriptor provides the relay's onion key (`ntor-onion-key`), Ed25519 identity key (`id ed25519`), and exit policy rules (`p accept/reject`).

### 2.2. Bandwidth-Weighted Path Selection (`directory.go`, `path-spec.txt §2.2`)
- **Role Assignment:**
  - **Guard:** Must have `Guard`, `Running`, `Valid` flags.
  - **Middle:** Must have `Fast`, `Running`, `Valid` flags.
  - **Exit:** Must have `Exit` (without `BadExit`) and its exit policy must accept the target port (e.g. 443 or 80).
- **Consensus Bandwidth Weights:** Parses `bandwidth-weights` and router `w Bandwidth=NN` lines. Weight factors (`Wgg`, `Wgd`, `Wmg`, `Wmm`, `Wee`, `Wed`) are applied to compute selection probabilities, ensuring circuit load is distributed proportionally across the network.
- **Subnet & Family Exclusion:**
  - Enforces subnet `/16` isolation so no two relays in the circuit share an IP `/16` prefix.
  - Checks declared node families (`sameFamily` via `family` or `MyFamily`), preventing relays owned by the same operator from co-occurring in a circuit.

### 2.3. TLS Link Handshake (`link.go`, `cell.go`)
1. Establishes a TLS connection to the Guard's `ORPort` with `InsecureSkipVerify: true` (Tor relays use self-signed certificates bound during the cell handshake).
2. **Cell Exchange:**
   - Client sends `VERSIONS` declaring support for link protocols 4 and 5.
   - Relay returns `VERSIONS`; protocol 4 must be supported.
   - Client parses `CERTS` cells, validating Ed25519 type 4 (Signing Key) and type 5 (TLS Link Key) certificates against the master identity key (`edID`).
   - Ignores `AUTH_CHALLENGE` and padding cells.
   - Client sends `NETINFO` populated with the current timestamp and relay IPv4/IPv6 address in valid TLV format.

### 2.4. 3-Hop Circuit Construction & ntor Handshake (`circuit.go`, `crypto.go`)
1. **CREATE2 (Guard):**
   - Generates an ephemeral X25519 keypair (`x`, `X`).
   - Sends `CREATE2` cell: Handshake Type `0x0002` (ntor) + Node ID (20B) + Onion Key `B` (32B) + Client Public Key `X` (32B).
   - Guard replies with `CREATED2`: `HLEN` (64) + Guard Public Key `Y` (32B) + Server Authentication tag `AUTH` (32B).
   - Client derives shared secrets `xy = x*Y` and `xb = x*B`, verifies server HMAC authentication, and extracts forward/backward keys (`Df`, `Db`, `Kf`, `Kb`) via HKDF-SHA256.
2. **EXTEND2 (Middle & Exit):**
   - Sends `RELAY_EARLY` with `RelayExtend2` containing link specifiers and ntor payload for the next hop.
   - The preceding hop extends the connection and returns `RelayExtended2`.
   - Client derives hop keys and appends the new `Hop` to the circuit.

### 2.5. Layered Onion Cryptography
- Every outgoing relay cell is encrypted from the innermost to outermost hop (`Exit → Middle → Guard`) with AES-128-CTR.
- Each intermediate relay strips one encryption layer before forwarding.
- Incoming cells are peeled (`Guard → Middle → Exit`) until `recognized == 0` and the SHA-1 backward digest matches.

### 2.6. Stream Multiplexing (`stream.go`)
- Implements standard Go `net.Conn`.
- Sends `RELAY_BEGIN` with target host and port (e.g. `check.torproject.org:443\x00`).
- Upon receiving `RELAY_CONNECTED`, the stream is ready.
- Exchanging data using `RELAY_DATA` cells (up to 498 payload bytes per cell).
- Clean closure via `RELAY_END`.

### 2.7. SENDME Flow Control (`circuit.go`, `stream.go`, `tor-spec.txt §7.3`)
- **Circuit Window:** Initialized to 1000 cells (`CircWindowInit`). Decrements on each received `RELAY_DATA`. When reaching 900 (`CircWindowThreshold`), client emits `RELAY_SENDME` (streamID 0) and replenishes 100 cells.
- **Stream Window:** Initialized to 500 cells (`StreamWindowInit`). Decrements on stream data received; at 450, client emits `RELAY_SENDME` (with stream ID) and replenishes 50 cells.
- **Packaging Window:** Outgoing `Write` operations pause and await incoming `RELAY_SENDME` confirmations when the packaging window drops to zero, preventing dropped transfers.

### 2.8. Persistent Guards on Disk (`guards.go`)
- Pins primary Guard relays in `~/.torogo/guards.json` (or customizable path).
- Reuses the same Guards for up to 60 days, defending against long-term statistical profiling attacks.
- Automatically rotates to a new Guard if consecutive failure counts reach 3 or the node is unlisted.

### 2.9. Onion Services v3 (`onion.go`, `rend-spec-v3.txt`)
- Parses 56-character Base32 `.onion` v3 addresses, validating version `0x03` and SHA3-256 checksums.
- Calculates consensus time periods (24h period with 12h offset) and blinded public keys.
- Computes HSDir hash ring indices (`CalculateHSDirIndex`) to identify responsible HSDir relays.
- Decrypts outer and inner descriptor layers (AES-256-CTR / HMAC-SHA256) and parses Introduction Points.
- Implements rendezvous primitives (`NewRendezvousCookie`, `EstablishRendezvous`, `BuildIntroduce1Payload`, `DeriveHSNtorKeys`).

### 2.10. Pluggable Transports Client (`pt.go`, `pt-spec.txt`)
- Pure Go RFC 1928 SOCKS5 client dialer to proxy ORPort TLS links through local bridges (obfs4, Snowflake, meek).
- Parser for standard Tor `Bridge` configuration lines.
- Tor PT v2.1 managed subprocess launcher reading `CMETHOD socks5` announcements.

### 2.11. Remote DNS Resolution & Zero Leakage (`circuit.go`, `client.go`)
- In standard TCP dials, hostnames are sent un-resolved in `RELAY_BEGIN`, resolved solely by the Exit Node.
- `client.Resolve(ctx, host)` uses `RELAY_RESOLVE` / `RELAY_RESOLVED` (`tor-spec.txt §6.4`) to perform remote DNS resolution over circuits without establishing TCP connections.

### 2.12. Local SOCKS5 Proxy Server (`socks_server.go`)
- Runs a local RFC 1928 SOCKS5 listener via `client.ListenSOCKS5("127.0.0.1:9050")`.
- Accepts standard connections, resolves domain names remotely over Tor, and acts as a drop-in replacement for the C `tor` daemon.

### 2.13. Tor Control Port Server (`control_server.go`, `control-spec.txt`)
- Listens on TCP port 9051 via `client.ListenControl("127.0.0.1:9051")`.
- Implements `AUTHENTICATE`, `PROTOCOLINFO`, `SIGNAL NEWNYM`, `GETINFO`, and `SETEVENTS` for compatibility with external Tor controllers.

---

## 3. Public API: `torogo.Client`

```go
type Client struct {
    mu        sync.RWMutex
    consensus *tor.Consensus
    guardMgr  *tor.GuardManager
    opts      clientOptions
    closed    bool
}
```

- **Thread-Safe Consensus Cache:** Caches the ~2MB consensus document within its validity window (`ValidAt(now)`).
- **`DialContext`:** Plugs directly into Go standard library dialer interfaces.
- **`HTTPClient` & `Transport`:** Provides out-of-the-box HTTP routing through Tor circuits.
- **`ListenSOCKS5` & `ListenControl`:** Exposes standard daemon listening ports.
