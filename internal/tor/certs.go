package tor

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"
	"time"
)

type AuthorityCert struct {
	Identity         *rsa.PublicKey
	Signing          *rsa.PublicKey
	IdentityDER      []byte
	SigningDER       []byte
	Fingerprint      string
	SigningKeyDigest string
	Published        time.Time
	Expires          time.Time
	Raw              []byte
}

func parseAuthorityCert(data []byte) (*AuthorityCert, error) {
	start := lineStart(data, []byte("dir-key-certificate-version"))
	if start < 0 {
		return nil, fmt.Errorf("tor: authority cert has no version line")
	}
	certKeyword := lineStart(data, []byte("dir-key-certification"))
	if certKeyword < 0 {
		return nil, fmt.Errorf("tor: authority cert has no certification line")
	}
	certEnd := lineEnd(data, certKeyword)
	certText := data[start:certEnd]

	fingerprint := strings.ToUpper(lineValue(certText, "fingerprint"))
	if fingerprint == "" {
		return nil, fmt.Errorf("tor: authority cert has no fingerprint")
	}

	idBlock, err := pemBlockAfter(certText, "dir-identity-key")
	if err != nil {
		return nil, err
	}
	signBlock, err := pemBlockAfter(certText, "dir-signing-key")
	if err != nil {
		return nil, err
	}
	identity, err := x509.ParsePKCS1PublicKey(idBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("tor: parse authority identity key: %w", err)
	}
	signing, err := x509.ParsePKCS1PublicKey(signBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("tor: parse authority signing key: %w", err)
	}
	identityDER := x509.MarshalPKCS1PublicKey(identity)
	signingDER := x509.MarshalPKCS1PublicKey(signing)
	computedFP := strings.ToUpper(hex.EncodeToString(sha1Sum(identityDER)))
	if computedFP != fingerprint {
		return nil, fmt.Errorf("tor: authority fingerprint mismatch: cert=%s computed=%s", fingerprint, computedFP)
	}
	signingDigest := strings.ToUpper(hex.EncodeToString(sha1Sum(signingDER)))

	published, err := parseCertTime(lineValue(certText, "dir-key-published"))
	if err != nil {
		return nil, fmt.Errorf("tor: parse dir-key-published: %w", err)
	}
	expires, err := parseCertTime(lineValue(certText, "dir-key-expires"))
	if err != nil {
		return nil, fmt.Errorf("tor: parse dir-key-expires: %w", err)
	}

	crossBlock, err := pemBlockAfter(certText, "dir-key-crosscert")
	if err != nil {
		return nil, err
	}
	idDigest := sha1Sum(identityDER)
	if !verifyRSARaw(signing, idDigest, crossBlock.Bytes) {
		return nil, fmt.Errorf("tor: authority crosscert signature invalid")
	}

	certBlock, err := pemBlockAfter(data, "dir-key-certification")
	if err != nil {
		return nil, err
	}
	certDigest := sha1Sum(certText)
	if !verifyRSARaw(identity, certDigest, certBlock.Bytes) {
		return nil, fmt.Errorf("tor: authority certification signature invalid")
	}

	return &AuthorityCert{
		Identity:         identity,
		Signing:          signing,
		IdentityDER:      identityDER,
		SigningDER:       signingDER,
		Fingerprint:      fingerprint,
		SigningKeyDigest: signingDigest,
		Published:        published,
		Expires:          expires,
		Raw:              append([]byte(nil), data...),
	}, nil
}

func (c *AuthorityCert) validAt(t time.Time) bool {
	return c != nil && !t.Before(c.Published) && !t.After(c.Expires)
}

func lineStart(data, keyword []byte) int {
	idx := bytes.Index(data, keyword)
	for idx >= 0 {
		if idx == 0 || data[idx-1] == '\n' {
			return idx
		}
		next := bytes.Index(data[idx+1:], keyword)
		if next < 0 {
			return -1
		}
		idx += 1 + next
	}
	return -1
}

func lineEnd(data []byte, start int) int {
	idx := bytes.IndexByte(data[start:], '\n')
	if idx < 0 {
		return len(data)
	}
	return start + idx + 1
}

func lineValue(data []byte, key string) string {
	prefix := key + " "
	for _, line := range bytes.Split(data, []byte{'\n'}) {
		s := string(line)
		if strings.HasPrefix(s, prefix) {
			return strings.TrimSpace(s[len(prefix):])
		}
	}
	return ""
}

func pemBlockAfter(data []byte, marker string) (*pem.Block, error) {
	idx := lineStart(data, []byte(marker))
	if idx < 0 {
		return nil, fmt.Errorf("tor: missing %s", marker)
	}
	block, _ := pem.Decode(data[idx:])
	if block == nil {
		return nil, fmt.Errorf("tor: no PEM block after %s", marker)
	}
	return block, nil
}

func parseCertTime(s string) (time.Time, error) {
	return time.ParseInLocation("2006-01-02 15:04:05", s, time.UTC)
}

func sha1Sum(data []byte) []byte {
	sum := sha1.Sum(data)
	return sum[:]
}

type Ed25519Extension struct {
	Type  byte
	Flags byte
	Data  []byte
}

type Ed25519Cert struct {
	Version    byte
	CertType   byte
	Expiration time.Time
	KeyType    byte
	Subject    [32]byte
	Extensions []Ed25519Extension
	Signature  [64]byte
	Signed     []byte
}

func parseEd25519Cert(data []byte) (*Ed25519Cert, error) {
	if len(data) < 1+1+4+1+32+1+64 {
		return nil, fmt.Errorf("tor: Ed25519 cert too short")
	}
	c := &Ed25519Cert{}
	c.Version = data[0]
	if c.Version != 1 {
		return nil, fmt.Errorf("tor: unsupported Ed25519 cert version %d", c.Version)
	}
	c.CertType = data[1]
	hours := binary.BigEndian.Uint32(data[2:6])
	c.Expiration = time.Unix(int64(hours)*3600, 0).UTC()
	c.KeyType = data[6]
	copy(c.Subject[:], data[7:39])
	nExt := int(data[39])
	off := 40
	for i := 0; i < nExt; i++ {
		if off+4 > len(data) {
			return nil, fmt.Errorf("tor: truncated Ed25519 cert extension")
		}
		n := int(binary.BigEndian.Uint16(data[off : off+2]))
		ext := Ed25519Extension{Type: data[off+2], Flags: data[off+3]}
		off += 4
		if off+n > len(data) {
			return nil, fmt.Errorf("tor: truncated Ed25519 cert extension data")
		}
		ext.Data = append([]byte(nil), data[off:off+n]...)
		off += n
		c.Extensions = append(c.Extensions, ext)
	}
	if off+64 != len(data) {
		return nil, fmt.Errorf("tor: Ed25519 cert length mismatch")
	}
	copy(c.Signature[:], data[off:off+64])
	c.Signed = append([]byte(nil), data[:off]...)
	return c, nil
}

func (c *Ed25519Cert) Verify(pub ed25519.PublicKey) bool {
	if len(pub) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(pub, c.Signed, c.Signature[:])
}

func (c *Ed25519Cert) Extension(t byte) []byte {
	for _, ext := range c.Extensions {
		if ext.Type == t {
			return ext.Data
		}
	}
	return nil
}

func (c *Ed25519Cert) validAt(t time.Time) bool {
	return !t.After(c.Expiration)
}
