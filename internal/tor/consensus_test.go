package tor

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"math/big"
	"testing"
	"time"
)

func TestParseConsensus(t *testing.T) {
	raw := `network-status-version 3 microdesc
vote-status consensus
consensus-method 38
valid-after 2026-11-25 00:00:00
fresh-until 2026-11-25 01:00:00
valid-until 2026-11-25 03:00:00
params Foo=1 Bar=2
r RelayOne AARRU4FvZE54rWG9Lt78faKFh6Q 2026-11-25 00:00:00 1.2.3.4 9001 0
a [2001:db8::1]:9001
m xYrorSAHvmEiXE4gvReBEco35m2AJ0/zOmsnQa6nz5o
s Fast Guard Running Valid
p accept 80,443
r RelayTwo AARRU4FvZE54rWG9Lt78faKFh6R 2026-11-25 00:00:00 5.6.7.8 9001 0
m yYrorSAHvmEiXE4gvReBEco35m2AJ0/zOmsnQa6nz5p
s Exit Fast Running Valid
p accept 443
`
	auth := &Authorities[0]
	cons, err := parseConsensus([]byte(raw), auth)
	if err != nil {
		t.Fatalf("parseConsensus error: %v", err)
	}

	if cons.Method != 38 {
		t.Errorf("expected method 38, got %d", cons.Method)
	}
	if len(cons.Routers) != 2 {
		t.Fatalf("expected 2 routers, got %d", len(cons.Routers))
	}

	r1 := cons.Routers[0]
	if r1.Nickname != "RelayOne" {
		t.Errorf("expected RelayOne, got %s", r1.Nickname)
	}
	if !r1.HasFlag("Guard") || !r1.HasFlag("Fast") {
		t.Errorf("expected Guard and Fast flags")
	}
	if !r1.HasMicrodesc {
		t.Errorf("expected HasMicrodesc = true")
	}
	if !r1.SummaryAcceptsPort(80) || !r1.SummaryAcceptsPort(443) {
		t.Errorf("RelayOne should accept 80 and 443")
	}
	if r1.SummaryAcceptsPort(22) {
		t.Errorf("RelayOne should reject 22")
	}

	now := time.Date(2026, 11, 25, 0, 30, 0, 0, time.UTC)
	if !cons.ValidAt(now) {
		t.Errorf("consensus should be valid at %v", now)
	}
	expired := time.Date(2026, 11, 25, 4, 0, 0, 0, time.UTC)
	if cons.ValidAt(expired) {
		t.Errorf("consensus should be invalid at %v", expired)
	}
	if cons.RequiredSignatures() != len(Authorities)/2+1 {
		t.Errorf("unexpected required signatures")
	}
}

func TestParseMicrodesc(t *testing.T) {
	raw := `onion-key
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAKQZ1kmo8X2H9dJeAiGmm2Oi0XMVYKXrFMnG9g3YnoTWO1nr03lJPvnM
JXj4hxx9XBHKkwr4bG2KeT8umxTVd2r/LOUxkgu/0nizaCs4tBqsauH6hL81tXSi
0vxYhR7Vvtt4K3idvlMvzDit+l8LseT4foqz2DDAAOO2noy6LjCvAgMBAAE=
-----END RSA PUBLIC KEY-----
ntor-onion-key 4nHCB4VXPLlWFiEDRaEGIi3+gTp9Bm7YawvJMVOYdFs
family-ids ed25519:WcnYw+UJooK1YJ/OLuqe+Hw9Y/CjR7pLqdAqc8DFGkc
id ed25519 rVmp6xX/6UAqMTPNGfkCN7M5CE/hNbo1qFTZBoUpGd4
p accept 80,443,8000-8080
`
	md, err := parseMicrodesc([]byte(raw))
	if err != nil {
		t.Fatalf("parseMicrodesc error: %v", err)
	}
	if len(md.NtorOnionKey) != 32 {
		t.Errorf("expected 32-byte ntor key, got %d", len(md.NtorOnionKey))
	}
	if len(md.Ed25519ID) != 32 {
		t.Errorf("expected 32-byte ed25519 id, got %d", len(md.Ed25519ID))
	}
	if !md.AcceptsPort(80) || !md.AcceptsPort(443) || !md.AcceptsPort(8080) {
		t.Errorf("expected accept for 80, 443, 8080")
	}
	if md.AcceptsPort(22) || md.AcceptsPort(8081) {
		t.Errorf("expected reject for 22, 8081")
	}
}

func TestPolicyAcceptsPort(t *testing.T) {
	tests := []struct {
		policies []string
		port     int
		want     bool
	}{
		{[]string{"accept 80,443"}, 80, true},
		{[]string{"accept 80,443"}, 443, true},
		{[]string{"accept 80,443"}, 22, false},
		{[]string{"reject 25", "accept *"}, 25, false},
		{[]string{"reject 25", "accept *"}, 80, true},
		{[]string{"accept 1-1024"}, 500, true},
		{[]string{"accept 1-1024"}, 1025, false},
		{[]string{"accept *:443"}, 443, true},
	}
	for _, tc := range tests {
		got := policyAcceptsPort(tc.policies, tc.port)
		if got != tc.want {
			t.Errorf("policyAcceptsPort(%v, %d) = %v, want %v", tc.policies, tc.port, got, tc.want)
		}
	}
}

func TestDecodeBase64(t *testing.T) {
	// Standard with padding
	raw := []byte("Hello Torogo 1234")
	std := base64.StdEncoding.EncodeToString(raw)
	dec, err := decodeBase64(std)
	if err != nil || !bytes.Equal(dec, raw) {
		t.Errorf("decodeBase64 failed for std: %v", err)
	}

	// Raw std without padding
	rawStd := base64.RawStdEncoding.EncodeToString(raw)
	dec2, err := decodeBase64(rawStd)
	if err != nil || !bytes.Equal(dec2, raw) {
		t.Errorf("decodeBase64 failed for rawStd: %v", err)
	}

	// Invalid
	if _, err := decodeBase64("!!!not-base64!!!"); err == nil {
		t.Errorf("expected error for invalid base64")
	}
}

func TestParseAndVerifyConsensusSignatures(t *testing.T) {
	// Generate mock authority RSA key
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pubKey := &privKey.PublicKey
	pubDER := x509.MarshalPKCS1PublicKey(pubKey)
	signDigest := sha1Sum(pubDER)
	signDigestHex := fmt.Sprintf("%X", signDigest)
	authFP := "0232AF901C31A04EE9848595AF9BB7620D4C5B2E" // dannenberg

	docPrefix := "network-status-version 3 microdesc\nvote-status consensus\nvalid-after 2026-11-25 00:00:00\nfresh-until 2026-11-25 01:00:00\nvalid-until 2026-11-25 03:00:00\ndirectory-signature "
	sum := sha256.Sum256([]byte(docPrefix))

	// Tor signs digest directly with raw RSA PKCS1 v1.5 padding:
	// EM = 0x00 || 0x01 || PS || 0x00 || Digest
	k := pubKey.Size()
	em := make([]byte, k)
	em[0] = 0
	em[1] = 1
	psLen := k - 3 - len(sum)
	for i := 0; i < psLen; i++ {
		em[2+i] = 0xff
	}
	em[2+psLen] = 0
	copy(em[k-len(sum):], sum[:])

	// Sign: s = em^d mod n
	c := new(big.Int).SetBytes(em)
	s := new(big.Int).Exp(c, privKey.D, privKey.N)
	sigBytes := s.FillBytes(make([]byte, k))
	sigB64 := base64.StdEncoding.EncodeToString(sigBytes)

	doc := fmt.Sprintf("%ssha256 %s %s\n-----BEGIN SIGNATURE-----\n%s\n-----END SIGNATURE-----\n",
		docPrefix, authFP, signDigestHex, sigB64)

	prefix, sigs, err := parseConsensusSignatures([]byte(doc))
	if err != nil {
		t.Fatalf("parseConsensusSignatures failed: %v", err)
	}
	if string(prefix) != docPrefix {
		t.Errorf("prefix mismatch: %q", string(prefix))
	}
	if len(sigs) != 1 {
		t.Fatalf("expected 1 sig, got %d", len(sigs))
	}
	if sigs[0].Algorithm != "sha256" || sigs[0].Identity != authFP || sigs[0].SigningKeyDigest != signDigestHex {
		t.Errorf("signature metadata mismatch: %+v", sigs[0])
	}

	// Verify using verifyConsensusSignatures
	mockCert := &AuthorityCert{
		Signing:          pubKey,
		Fingerprint:      authFP,
		SigningKeyDigest: signDigestHex,
		Published:        time.Now().Add(-1 * time.Hour),
		Expires:          time.Now().Add(24 * time.Hour),
	}
	certs := map[string]*AuthorityCert{
		authFP: mockCert,
	}

	valid, err := verifyConsensusSignatures([]byte(doc), certs, time.Now())
	if err != nil {
		t.Fatalf("verifyConsensusSignatures failed: %v", err)
	}
	if !valid[authFP] {
		t.Errorf("expected signature from %s to be valid", authFP)
	}
}
