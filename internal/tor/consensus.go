package tor

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

type Authority struct {
	Nickname    string
	Fingerprint string
	IP          string
	DirPort     int
	ORPort      int
}

var Authorities = []Authority{
	{Nickname: "dannenberg", Fingerprint: "0232AF901C31A04EE9848595AF9BB7620D4C5B2E", IP: "193.23.244.244", DirPort: 80, ORPort: 443},
	{Nickname: "longclaw", Fingerprint: "23D15D965BC35114467363C165C4F724B64B4F66", IP: "199.58.81.140", DirPort: 80, ORPort: 443},
	{Nickname: "bastet", Fingerprint: "27102BC123E7AF1D4741AE047E160C91ADC76B21", IP: "204.13.164.118", DirPort: 80, ORPort: 443},
	{Nickname: "sekhmet", Fingerprint: "E30CF7B3DFA63FBDC5FC9E46EC75C543AB6D7403", IP: "204.13.164.118", DirPort: 80, ORPort: 443},
	{Nickname: "tor26", Fingerprint: "2F3DF9CA0E5D36F2685A2DA67184EB8DCB8CBA8C", IP: "217.196.147.77", DirPort: 80, ORPort: 443},
	{Nickname: "maatuska", Fingerprint: "49015F787433103580E3B66A1707A00E60F2D15B", IP: "91.223.231.13", DirPort: 443, ORPort: 80},
	{Nickname: "faravahar", Fingerprint: "70849B868D606BAECFB6128C5E3D782029AA394F", IP: "216.218.219.41", DirPort: 80, ORPort: 443},
	{Nickname: "dizum", Fingerprint: "E8A9C45EDE6D711294FADF8E7951F4DE6CA56B58", IP: "45.66.35.11", DirPort: 80, ORPort: 443},
	{Nickname: "gabelmoo", Fingerprint: "ED03BB616EB2F60BEC80151114BB25CEF515B226", IP: "131.188.40.189", DirPort: 80, ORPort: 443},
	{Nickname: "moria1", Fingerprint: "F533C81CEF0BC0267857C99B2F471ADF249FA232", IP: "128.31.0.39", DirPort: 9231, ORPort: 9201},
}

func authorityByFingerprint(fp string) *Authority {
	fp = strings.ToUpper(strings.TrimSpace(fp))
	for i := range Authorities {
		if Authorities[i].Fingerprint == fp {
			return &Authorities[i]
		}
	}
	return nil
}

type RouterStatus struct {
	Nickname      string
	Identity      [20]byte
	Digest        [20]byte
	Published     time.Time
	IP            net.IP
	ORPort        uint16
	DirPort       uint16
	Flags         map[string]bool
	MicrodescHash [32]byte
	HasMicrodesc  bool
	PortSummary   []string
	IPv6          string
	Bandwidth     uint64
}

func (r *RouterStatus) HasFlag(flag string) bool {
	return r != nil && r.Flags[flag]
}

func (r *RouterStatus) SummaryAcceptsPort(port int) bool {
	return policyAcceptsPort(r.PortSummary, port)
}

type Consensus struct {
	Raw              []byte
	ValidAfter       time.Time
	FreshUntil       time.Time
	ValidUntil       time.Time
	Method           int
	Routers          []*RouterStatus
	Params           map[string]string
	BandwidthWeights map[string]int64
	Source           *Authority
	SignatureCount   int
}

func parseConsensus(raw []byte, source *Authority) (*Consensus, error) {
	c := &Consensus{
		Raw:              append([]byte(nil), raw...),
		Params:           map[string]string{},
		BandwidthWeights: map[string]int64{},
		Source:           source,
	}
	lines := bytes.Split(raw, []byte{'\n'})
	var current *RouterStatus
	for _, rawLine := range lines {
		line := strings.TrimRight(string(rawLine), "\r")
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "network-status-version ") {
			continue
		}
		if strings.HasPrefix(line, "valid-after ") {
			t, err := parseConsensusTime(strings.TrimPrefix(line, "valid-after "))
			if err != nil {
				return nil, err
			}
			c.ValidAfter = t
			continue
		}
		if strings.HasPrefix(line, "fresh-until ") {
			t, err := parseConsensusTime(strings.TrimPrefix(line, "fresh-until "))
			if err != nil {
				return nil, err
			}
			c.FreshUntil = t
			continue
		}
		if strings.HasPrefix(line, "valid-until ") {
			t, err := parseConsensusTime(strings.TrimPrefix(line, "valid-until "))
			if err != nil {
				return nil, err
			}
			c.ValidUntil = t
			continue
		}
		if strings.HasPrefix(line, "consensus-method ") {
			c.Method, _ = strconv.Atoi(strings.TrimPrefix(line, "consensus-method "))
			continue
		}
		if strings.HasPrefix(line, "params ") {
			for _, p := range strings.Fields(strings.TrimPrefix(line, "params ")) {
				k, v, ok := strings.Cut(p, "=")
				if ok {
					c.Params[k] = v
				}
			}
			continue
		}
		if strings.HasPrefix(line, "bandwidth-weights ") {
			for _, p := range strings.Fields(strings.TrimPrefix(line, "bandwidth-weights ")) {
				k, v, ok := strings.Cut(p, "=")
				if ok {
					val, _ := strconv.ParseInt(v, 10, 64)
					c.BandwidthWeights[k] = val
				}
			}
			continue
		}
		if strings.HasPrefix(line, "r ") {
			rs, err := parseRouterStatus(line)
			if err != nil {
				return nil, err
			}
			current = rs
			c.Routers = append(c.Routers, rs)
			continue
		}
		if current == nil {
			continue
		}
		switch {
		case strings.HasPrefix(line, "m "):
			h, err := decodeBase64(strings.TrimSpace(line[2:]))
			if err != nil || len(h) != 32 {
				return nil, fmt.Errorf("tor: bad microdesc hash in consensus")
			}
			copy(current.MicrodescHash[:], h)
			current.HasMicrodesc = true
		case strings.HasPrefix(line, "s "):
			for _, f := range strings.Fields(strings.TrimPrefix(line, "s ")) {
				current.Flags[f] = true
			}
		case strings.HasPrefix(line, "p "):
			current.PortSummary = append(current.PortSummary, strings.TrimSpace(line[2:]))
		case strings.HasPrefix(line, "w "):
			for _, p := range strings.Fields(strings.TrimPrefix(line, "w ")) {
				if strings.HasPrefix(p, "Bandwidth=") {
					bw, _ := strconv.ParseUint(strings.TrimPrefix(p, "Bandwidth="), 10, 64)
					current.Bandwidth = bw
				}
			}
		case strings.HasPrefix(line, "a "):
			current.IPv6 = strings.TrimSpace(line[2:])
		}
	}
	if c.ValidAfter.IsZero() || c.ValidUntil.IsZero() {
		return nil, fmt.Errorf("tor: consensus missing validity timestamps")
	}
	return c, nil
}

func parseRouterStatus(line string) (*RouterStatus, error) {
	f := strings.Fields(line)
	if len(f) < 7 {
		return nil, fmt.Errorf("tor: malformed r line (fields=%d): %q", len(f), line)
	}
	id, err := decodeBase64(f[2])
	if err != nil || len(id) != 20 {
		return nil, fmt.Errorf("tor: bad router identity")
	}
	rs := &RouterStatus{
		Nickname: f[1],
		Flags:    map[string]bool{},
	}
	copy(rs.Identity[:], id)

	// The r line format is:
	// r <nickname> <identity> <digest> <published date> <published time> <ip> <orport> <dirport>
	// Some consensus versions omit the digest field, giving 8 fields instead of 9.
	// Detect which format we have by checking if f[3] is a valid 20-byte base64 digest.
	digestStart := 3
	if len(f) > 3 {
		d, derr := decodeBase64(f[3])
		if derr == nil && len(d) == 20 {
			copy(rs.Digest[:], d)
			digestStart = 4
		}
	}

	publishedStr := f[digestStart] + " " + f[digestStart+1]
	published, err := parseConsensusTime(publishedStr)
	if err != nil {
		return nil, err
	}
	rs.Published = published

	ip := net.ParseIP(f[digestStart+2])
	if ip == nil {
		return nil, fmt.Errorf("tor: bad router IP %q", f[digestStart+2])
	}
	rs.IP = ip

	orPort, err := strconv.Atoi(f[digestStart+3])
	if err != nil || orPort <= 0 || orPort > 65535 {
		return nil, fmt.Errorf("tor: bad ORPort %q", f[digestStart+3])
	}
	rs.ORPort = uint16(orPort)

	if len(f) > digestStart+4 {
		dirPort, _ := strconv.Atoi(f[digestStart+4])
		rs.DirPort = uint16(dirPort)
	}
	return rs, nil
}

func parseConsensusTime(s string) (time.Time, error) {
	return time.ParseInLocation("2006-01-02 15:04:05", strings.TrimSpace(s), time.UTC)
}

type consensusSig struct {
	Algorithm        string
	Identity         string
	SigningKeyDigest string
	Signature        []byte
}

func parseConsensusSignatures(raw []byte) ([]byte, []consensusSig, error) {
	sigIdx := bytes.Index(raw, []byte("\ndirectory-signature "))
	if sigIdx == -1 {
		if bytes.HasPrefix(raw, []byte("directory-signature ")) {
			sigIdx = 0
		} else {
			return nil, nil, fmt.Errorf("tor: consensus has no directory-signature lines")
		}
	} else {
		sigIdx++
	}
	prefix := raw[:sigIdx+len("directory-signature ")]

	var sigs []consensusSig
	lines := bytes.Split(raw[sigIdx:], []byte{'\n'})
	var currentSig *consensusSig
	var inSigBlock bool
	var sigLines []string

	for _, rawLine := range lines {
		line := strings.TrimRight(string(rawLine), "\r")
		if strings.HasPrefix(line, "directory-signature ") {
			fields := strings.Fields(line)
			var alg, identity, digest string
			switch len(fields) {
			case 3:
				alg, identity, digest = "sha1", fields[1], fields[2]
			case 4:
				alg, identity, digest = fields[1], fields[2], fields[3]
			default:
				return nil, nil, fmt.Errorf("tor: malformed directory-signature line: %q", line)
			}
			currentSig = &consensusSig{
				Algorithm:        strings.ToLower(alg),
				Identity:         strings.ToUpper(identity),
				SigningKeyDigest: strings.ToUpper(digest),
			}
			continue
		}
		if currentSig != nil && strings.HasPrefix(line, "-----BEGIN SIGNATURE-----") {
			inSigBlock = true
			sigLines = nil
			continue
		}
		if inSigBlock {
			if strings.HasPrefix(line, "-----END SIGNATURE-----") {
				inSigBlock = false
				rawSig, err := decodeBase64(strings.Join(sigLines, ""))
				if err != nil {
					return nil, nil, fmt.Errorf("tor: bad consensus signature base64: %w", err)
				}
				currentSig.Signature = rawSig
				sigs = append(sigs, *currentSig)
				currentSig = nil
				continue
			}
			sigLines = append(sigLines, strings.TrimSpace(line))
		}
	}

	if len(sigs) == 0 {
		return nil, nil, fmt.Errorf("tor: consensus has no valid directory signatures")
	}
	return prefix, sigs, nil
}

func verifyConsensusSignatures(raw []byte, certs map[string]*AuthorityCert, now time.Time) (map[string]bool, error) {
	prefix, sigs, err := parseConsensusSignatures(raw)
	if err != nil {
		return nil, err
	}
	valid := map[string]bool{}
	for _, sig := range sigs {
		cert := certs[sig.Identity]
		if cert == nil || !cert.validAt(now) {
			continue
		}
		if cert.SigningKeyDigest != sig.SigningKeyDigest {
			continue
		}
		var ok bool
		switch sig.Algorithm {
		case "sha1", "":
			sum := sha1.Sum(prefix)
			ok = verifyRSARaw(cert.Signing, sum[:], sig.Signature)
		case "sha256":
			sum := sha256.Sum256(prefix)
			ok = verifyRSARaw(cert.Signing, sum[:], sig.Signature)
		default:
			continue
		}
		if ok {
			valid[sig.Identity] = true
		}
	}
	return valid, nil
}

func (c *Consensus) ValidAt(t time.Time) bool {
	return !t.Before(c.ValidAfter) && !t.After(c.ValidUntil)
}

func (c *Consensus) RequiredSignatures() int {
	return len(Authorities)/2 + 1
}

type Microdesc struct {
	Raw          []byte
	NtorOnionKey []byte
	Ed25519ID    []byte
	ExitPolicy   []string
	Family       []string
}

func parseMicrodesc(raw []byte) (*Microdesc, error) {
	m := &Microdesc{Raw: append([]byte(nil), raw...)}
	for _, rawLine := range bytes.Split(raw, []byte{'\n'}) {
		line := strings.TrimRight(string(rawLine), "\r")
		switch {
		case strings.HasPrefix(line, "ntor-onion-key "):
			v, err := decodeBase64(strings.TrimSpace(strings.TrimPrefix(line, "ntor-onion-key ")))
			if err != nil || len(v) != 32 {
				return nil, fmt.Errorf("tor: bad ntor-onion-key in microdesc")
			}
			m.NtorOnionKey = v
		case strings.HasPrefix(line, "id ed25519 "):
			v, err := decodeBase64(strings.TrimSpace(strings.TrimPrefix(line, "id ed25519 ")))
			if err != nil || len(v) != 32 {
				return nil, fmt.Errorf("tor: bad ed25519 id in microdesc")
			}
			m.Ed25519ID = v
		case strings.HasPrefix(line, "p "):
			m.ExitPolicy = append(m.ExitPolicy, strings.TrimSpace(line[2:]))
		case strings.HasPrefix(line, "family "):
			for _, fam := range strings.Fields(strings.TrimPrefix(line, "family ")) {
				fam = strings.TrimPrefix(fam, "$")
				m.Family = append(m.Family, strings.ToUpper(fam))
			}
		}
	}
	if len(m.NtorOnionKey) == 0 || len(m.Ed25519ID) == 0 {
		return nil, fmt.Errorf("tor: microdesc missing ntor or ed25519 key")
	}
	return m, nil
}

func (m *Microdesc) AcceptsPort(port int) bool {
	return policyAcceptsPort(m.ExitPolicy, port)
}

func policyAcceptsPort(lines []string, port int) bool {
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		accept := fields[0] == "accept"
		if !accept && fields[0] != "reject" {
			continue
		}
		for _, p := range strings.Split(fields[1], ",") {
			if policyTokenMatchesPort(p, port) {
				return accept
			}
		}
	}
	return false
}

func policyTokenMatchesPort(token string, port int) bool {
	token = strings.TrimSpace(token)
	if token == "" {
		return false
	}
	if token == "*" {
		return true
	}
	if idx := strings.LastIndexByte(token, ':'); idx >= 0 && !strings.Contains(token[idx:], "-") {
		addr := token[:idx]
		if addr != "" && addr != "*" && !strings.HasPrefix(addr, "[") {
			return false
		}
		token = token[idx+1:]
	}
	lo, hi := token, token
	if a, b, ok := strings.Cut(token, "-"); ok {
		lo, hi = a, b
	}
	l, err1 := strconv.Atoi(lo)
	h, err2 := strconv.Atoi(hi)
	if err1 != nil || err2 != nil {
		return false
	}
	return port >= l && port <= h
}

func decodeBase64(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return nil, fmt.Errorf("tor: invalid base64 %q", s)
}

func base64Hash(h [32]byte) string {
	return base64.StdEncoding.EncodeToString(h[:])
}

func uint16At(b []byte) uint16 {
	return binary.BigEndian.Uint16(b)
}
