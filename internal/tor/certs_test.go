package tor

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"testing"
	"time"
)

func TestParseEd25519Cert(t *testing.T) {
	// Generate signing key (master) and certified subject key
	pubMaster, privMaster, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubSubject, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Build Ed25519 certificate
	// VERSION (1) = 0x01
	// CERT_TYPE (1) = 0x04
	// EXPIRATION (4) = hours
	// CERT_KEY_TYPE (1) = 0x01
	// CERTIFIED_KEY (32) = pubSubject
	// N_EXTENSIONS (1) = 1
	// Extension 1:
	//   ExtLen (2) = 32
	//   ExtType (1) = 0x04 (signed-with-ed25519-key)
	//   ExtFlags (1) = 0x00
	//   ExtData (32) = pubMaster
	// SIGNATURE (64)

	expHours := uint32(time.Now().Add(24*time.Hour).Unix() / 3600)
	var body []byte
	body = append(body, 1)                      // Version
	body = append(body, 4)                      // CertType
	expBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(expBytes, expHours)
	body = append(body, expBytes...)            // Expiration
	body = append(body, 1)                      // KeyType
	body = append(body, pubSubject...)          // Subject

	// Extensions
	body = append(body, 1)                      // N_EXTENSIONS = 1
	extLenBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(extLenBytes, 32)
	body = append(body, extLenBytes...)         // ExtLen = 32
	body = append(body, 4)                      // ExtType = 4
	body = append(body, 0)                      // ExtFlags = 0
	body = append(body, pubMaster...)           // ExtData = pubMaster

	// Sign body
	sig := ed25519.Sign(privMaster, body)
	fullCert := append(body, sig...)

	cert, err := parseEd25519Cert(fullCert)
	if err != nil {
		t.Fatalf("parseEd25519Cert error: %v", err)
	}
	if cert.Version != 1 {
		t.Errorf("version: expected 1, got %d", cert.Version)
	}
	if cert.CertType != 4 {
		t.Errorf("certType: expected 4, got %d", cert.CertType)
	}
	if !cert.validAt(time.Now()) {
		t.Errorf("expected cert to be valid now")
	}
	if !cert.Verify(pubMaster) {
		t.Errorf("expected signature verification with master key to succeed")
	}

	ext4 := cert.Extension(4)
	if len(ext4) != 32 {
		t.Errorf("expected 32-byte extension 4, got %d", len(ext4))
	}
	if string(ext4) != string(pubMaster) {
		t.Errorf("extension 4 data does not match master public key")
	}
	if cert.Extension(99) != nil {
		t.Errorf("expected nil for nonexistent extension")
	}
}

func TestParseEd25519CertErrors(t *testing.T) {
	// Too short
	if _, err := parseEd25519Cert([]byte{1, 2, 3}); err == nil {
		t.Error("expected error for short cert")
	}

	// Wrong version
	badVer := make([]byte, 105)
	badVer[0] = 2 // version 2 unsupported
	if _, err := parseEd25519Cert(badVer); err == nil {
		t.Error("expected error for unsupported version")
	}
}

func TestEmbeddedAuthorityCerts(t *testing.T) {
	certs, err := EmbeddedAuthorityCerts()
	if err != nil {
		t.Fatalf("EmbeddedAuthorityCerts failed: %v", err)
	}
	if len(certs) == 0 {
		t.Fatal("expected at least one embedded authority cert")
	}
	now := time.Now().UTC()
	validCount := 0
	for _, c := range certs {
		if c.Fingerprint == "" {
			t.Error("cert missing fingerprint")
		}
		if c.Signing == nil || c.Identity == nil {
			t.Error("cert missing RSA keys")
		}
		if c.validAt(now) {
			validCount++
		}
	}
	if validCount == 0 {
		t.Errorf("expected at least one currently valid embedded authority cert")
	}
}
