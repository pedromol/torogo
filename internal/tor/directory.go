package tor

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	maxConsensusBytes = 20 << 20
	maxCertBytes      = 64 << 10
	maxMicrodescBytes = 2 << 20
)

func fetchURL(ctx context.Context, ip string, port int, path string, max int64) ([]byte, error) {
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	d := net.Dialer{Timeout: 10 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	deadline := time.Now().Add(30 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)

	reqText := fmt.Sprintf("GET %s HTTP/1.0\r\nHost: %s\r\nAccept-Encoding: identity\r\nConnection: close\r\nUser-Agent: torogo\r\n\r\n", path, addr)
	if _, err := io.WriteString(conn, reqText); err != nil {
		return nil, err
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodGet})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("tor: directory %s returned HTTP %d", addr+path, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > max {
		return nil, fmt.Errorf("tor: directory response too large")
	}
	return body, nil
}

func shuffledAuthorities() []*Authority {
	out := make([]*Authority, len(Authorities))
	for i := range Authorities {
		out[i] = &Authorities[i]
	}
	for i := len(out) - 1; i > 0; i-- {
		j := randomInt(i + 1)
		out[i], out[j] = out[j], out[i]
	}
	return out
}

func FetchConsensus(ctx context.Context) (*Consensus, error) {
	now := time.Now().UTC()
	var lastErr error
	for _, auth := range shuffledAuthorities() {
		raw, err := fetchURL(ctx, auth.IP, auth.DirPort, "/tor/status-vote/current/consensus-microdesc", maxConsensusBytes)
		if err != nil {
			lastErr = fmt.Errorf("%s: %w", auth.Nickname, err)
			continue
		}
		if !strings.HasPrefix(string(raw), "network-status-version 3 microdesc") {
			lastErr = fmt.Errorf("%s: not a microdesc consensus", auth.Nickname)
			continue
		}
		cons, err := parseConsensus(raw, auth)
		if err != nil {
			lastErr = fmt.Errorf("%s: %w", auth.Nickname, err)
			continue
		}
		if !cons.ValidAt(now) {
			lastErr = fmt.Errorf("%s: consensus outside validity window", auth.Nickname)
			continue
		}
		certs, err := fetchCertsForConsensus(ctx, raw, auth)
		if err != nil {
			lastErr = fmt.Errorf("%s: %w", auth.Nickname, err)
			continue
		}
		valid, err := verifyConsensusSignatures(raw, certs, now)
		if err != nil {
			lastErr = fmt.Errorf("%s: %w", auth.Nickname, err)
			continue
		}
		cons.SignatureCount = len(valid)
		if len(valid) < cons.RequiredSignatures() {
			lastErr = fmt.Errorf("%s: only %d/%d valid authority signatures", auth.Nickname, len(valid), cons.RequiredSignatures())
			continue
		}
		return cons, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("tor: no authorities configured")
	}
	return nil, fmt.Errorf("tor: could not fetch a valid consensus: %w", lastErr)
}

type certFetchResult struct {
	fingerprint string
	cert        *AuthorityCert
	err         error
}

func fetchCertsForConsensus(ctx context.Context, raw []byte, source *Authority) (map[string]*AuthorityCert, error) {
	_, sigs, err := parseConsensusSignatures(raw)
	if err != nil {
		return nil, err
	}
	ids := map[string]bool{}
	for _, sig := range sigs {
		if authorityByFingerprint(sig.Identity) != nil {
			ids[sig.Identity] = true
		}
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("tor: consensus has no recognized authority signatures")
	}

	now := time.Now().UTC()
	results := make(chan certFetchResult, len(ids))
	var wg sync.WaitGroup
	for fp := range ids {
		fp := fp
		wg.Add(1)
		go func() {
			defer wg.Done()
			cert, err := fetchAuthorityCert(ctx, fp, source, now)
			results <- certFetchResult{fingerprint: fp, cert: cert, err: err}
		}()
	}
	wg.Wait()
	close(results)

	out := map[string]*AuthorityCert{}
	for r := range results {
		if r.err == nil && r.cert != nil {
			out[r.fingerprint] = r.cert
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("tor: could not fetch any authority key certificates")
	}
	return out, nil
}

func fetchAuthorityCert(ctx context.Context, fingerprint string, preferred *Authority, now time.Time) (*AuthorityCert, error) {
	fingerprint = strings.ToUpper(fingerprint)
	if authorityByFingerprint(fingerprint) == nil {
		return nil, fmt.Errorf("tor: unrecognized authority fingerprint %s", fingerprint)
	}
	var order []*Authority
	if preferred != nil {
		order = append(order, preferred)
	}
	for _, a := range shuffledAuthorities() {
		if preferred == nil || a.Fingerprint != preferred.Fingerprint {
			order = append(order, a)
		}
	}
	var lastErr error
	for _, a := range order {
		raw, err := fetchURL(ctx, a.IP, a.DirPort, "/tor/keys/fp/"+fingerprint, maxCertBytes)
		if err != nil {
			lastErr = err
			continue
		}
		cert, err := parseAuthorityCert(raw)
		if err != nil {
			lastErr = err
			continue
		}
		if cert.Fingerprint != fingerprint {
			lastErr = fmt.Errorf("tor: fetched cert fingerprint mismatch")
			continue
		}
		if !cert.validAt(now) {
			lastErr = fmt.Errorf("tor: authority cert outside validity window")
			continue
		}
		return cert, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("tor: authority cert not found")
	}
	return nil, lastErr
}

func FetchMicrodesc(ctx context.Context, cons *Consensus, rs *RouterStatus) (*Microdesc, error) {
	if rs == nil || !rs.HasMicrodesc {
		return nil, fmt.Errorf("tor: router has no microdescriptor hash")
	}
	hashPath := base64.RawStdEncoding.EncodeToString(rs.MicrodescHash[:])
	var order []*Authority
	if cons.Source != nil {
		order = append(order, cons.Source)
	}
	for _, a := range shuffledAuthorities() {
		if cons.Source == nil || a.Fingerprint != cons.Source.Fingerprint {
			order = append(order, a)
		}
	}
	var lastErr error
	for _, a := range order {
		raw, err := fetchURL(ctx, a.IP, a.DirPort, "/tor/micro/d/"+hashPath, maxMicrodescBytes)
		if err != nil {
			lastErr = err
			continue
		}
		if sha256.Sum256(raw) != rs.MicrodescHash {
			lastErr = fmt.Errorf("tor: microdescriptor hash mismatch")
			continue
		}
		md, err := parseMicrodesc(raw)
		if err != nil {
			lastErr = err
			continue
		}
		return md, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("tor: microdescriptor not found")
	}
	return nil, lastErr
}

type Path struct {
	Routers    [3]*RouterStatus
	Microdescs [3]*Microdesc
}

func SelectPath(ctx context.Context, cons *Consensus) (*Path, error) {
	return SelectPathWithGuards(ctx, cons, 443, nil)
}

func SelectPathForPort(ctx context.Context, cons *Consensus, targetPort int) (*Path, error) {
	return SelectPathWithGuards(ctx, cons, targetPort, nil)
}

func SelectPathWithGuards(ctx context.Context, cons *Consensus, targetPort int, gm *GuardManager) (*Path, error) {
	var guards, middles, exits []*RouterStatus
	for _, rs := range cons.Routers {
		if rs.HasFlag("NoEdConsensus") || !rs.HasFlag("Running") || !rs.HasFlag("Valid") {
			continue
		}
		if rs.HasFlag("Guard") {
			guards = append(guards, rs)
		}
		if rs.HasFlag("Fast") {
			middles = append(middles, rs)
		}
		if rs.HasFlag("Exit") && !rs.HasFlag("BadExit") {
			exits = append(exits, rs)
		}
	}
	shuffleRouters(guards)
	shuffleRouters(middles)
	shuffleRouters(exits)

	var path Path
	var err error

	if gm != nil {
		grs, gmd, gerr := gm.SelectGuard(ctx, cons)
		if gerr == nil && grs != nil && gmd != nil {
			path.Routers[0], path.Microdescs[0] = grs, gmd
		} else {
			err = gerr
		}
	}

	if path.Routers[0] == nil {
		for _, rs := range guards {
			md, mdErr := FetchMicrodesc(ctx, cons, rs)
			if mdErr != nil {
				err = mdErr
				continue
			}
			path.Routers[0], path.Microdescs[0] = rs, md
			break
		}
	}
	if path.Routers[0] == nil {
		return nil, fmt.Errorf("tor: no usable guard: %w", err)
	}

	err = nil
	for _, rs := range middles {
		if sameRelay(rs, path.Routers[0]) || sameSlash16(rs.IP, path.Routers[0].IP) {
			continue
		}
		md, mdErr := FetchMicrodesc(ctx, cons, rs)
		if mdErr != nil {
			err = mdErr
			continue
		}
		path.Routers[1], path.Microdescs[1] = rs, md
		break
	}
	if path.Routers[1] == nil {
		return nil, fmt.Errorf("tor: no usable middle relay: %w", err)
	}

	err = nil
	for _, rs := range exits {
		if sameRelay(rs, path.Routers[0]) || sameRelay(rs, path.Routers[1]) {
			continue
		}
		if sameSlash16(rs.IP, path.Routers[0].IP) || sameSlash16(rs.IP, path.Routers[1].IP) {
			continue
		}
		md, mdErr := FetchMicrodesc(ctx, cons, rs)
		if mdErr != nil {
			err = mdErr
			continue
		}
		if targetPort > 0 && !md.AcceptsPort(targetPort) {
			err = fmt.Errorf("tor: exit policy does not accept port %d", targetPort)
			continue
		}
		path.Routers[2], path.Microdescs[2] = rs, md
		break
	}
	if path.Routers[2] == nil {
		return nil, fmt.Errorf("tor: no usable exit relay: %w", err)
	}
	return &path, nil
}

func sameRelay(a, b *RouterStatus) bool {
	return a == b || (a != nil && b != nil && a.Identity == b.Identity)
}

func sameSlash16(a, b net.IP) bool {
	a4, b4 := a.To4(), b.To4()
	if a4 == nil || b4 == nil {
		return a.Equal(b)
	}
	return a4[0] == b4[0] && a4[1] == b4[1]
}

func shuffleRouters(routers []*RouterStatus) {
	for i := len(routers) - 1; i > 0; i-- {
		j := randomInt(i + 1)
		routers[i], routers[j] = routers[j], routers[i]
	}
}

func randomInt(n int) int {
	if n <= 1 {
		return 0
	}
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		panic(err)
	}
	return int(v.Int64())
}
