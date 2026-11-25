package tor

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"testing"
	"time"
)

func TestOnionV3EncodingAndDecoding(t *testing.T) {
	var pubkey [32]byte
	if _, err := rand.Read(pubkey[:]); err != nil {
		t.Fatalf("rand failed: %v", err)
	}

	addrStr := EncodeOnionV3(pubkey)
	if len(addrStr) != 56+6 { // 56 base32 chars + ".onion"
		t.Fatalf("expected length 62, got %d (%s)", len(addrStr), addrStr)
	}

	parsed, err := ParseOnionV3(addrStr)
	if err != nil {
		t.Fatalf("ParseOnionV3 failed: %v", err)
	}

	if parsed.PublicKey != pubkey {
		t.Fatalf("parsed pubkey does not match original")
	}
	if parsed.Version != OnionV3Version {
		t.Fatalf("expected version %d, got %d", OnionV3Version, parsed.Version)
	}
	if parsed.Address != addrStr {
		t.Fatalf("expected address %s, got %s", addrStr, parsed.Address)
	}
}

func TestKnownOnionV3Address(t *testing.T) {
	// DuckDuckGo official v3 onion service
	ddg := "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion"
	parsed, err := ParseOnionV3(ddg)
	if err != nil {
		t.Fatalf("failed to parse DuckDuckGo v3 onion address: %v", err)
	}
	if parsed.Version != 3 {
		t.Fatalf("expected version 3, got %d", parsed.Version)
	}

	// Verify re-encoding produces the same string
	reEncoded := EncodeOnionV3(parsed.PublicKey)
	if reEncoded != ddg {
		t.Fatalf("re-encoded mismatch: expected %s, got %s", ddg, reEncoded)
	}
}

func TestInvalidOnionV3Addresses(t *testing.T) {
	// Too short
	if _, err := ParseOnionV3("tooshort.onion"); err == nil {
		t.Fatalf("expected error for short onion address")
	}

	// Corrupted checksum
	badChecksum := "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczbb.onion"
	if _, err := ParseOnionV3(badChecksum); err == nil {
		t.Fatalf("expected error for corrupted checksum")
	}
}

func TestTimePeriod(t *testing.T) {
	// A fixed point in time
	refTime := time.Date(2026, 1, 1, 18, 0, 0, 0, time.UTC)
	tp := CalculateTimePeriod(refTime)
	if tp == 0 {
		t.Fatalf("expected non-zero time period")
	}

	// 24 hours later should be tp + 1
	nextDay := refTime.Add(24 * time.Hour)
	tpNext := CalculateTimePeriod(nextDay)
	if tpNext != tp+1 {
		t.Fatalf("expected tpNext to be %d, got %d", tp+1, tpNext)
	}
}

func TestRendezvousCookie(t *testing.T) {
	c1, err := NewRendezvousCookie()
	if err != nil {
		t.Fatalf("NewRendezvousCookie failed: %v", err)
	}
	c2, err := NewRendezvousCookie()
	if err != nil {
		t.Fatalf("NewRendezvousCookie failed: %v", err)
	}
	if c1 == c2 {
		t.Fatalf("cookies should be unique")
	}
}

func TestDeriveBlindedKeyAndSubcredential(t *testing.T) {
	var pubkey [32]byte
	copy(pubkey[:], []byte("01234567890123456789012345678901"))

	blinded := DeriveBlindedKey(pubkey, 12345)
	if blinded == pubkey {
		t.Fatalf("blinded key must differ from public key")
	}

	subcred := DeriveSubcredential(pubkey, blinded)
	if subcred == [32]byte{} {
		t.Fatalf("subcred should not be empty")
	}

	// Invariant: same inputs produce same outputs
	blinded2 := DeriveBlindedKey(pubkey, 12345)
	if blinded != blinded2 {
		t.Fatalf("derivation should be deterministic")
	}
}

func TestHSDirRingAndSelection(t *testing.T) {
	var id1, id2, id3 [20]byte
	copy(id1[:], []byte("hsdir111111111111111"))
	copy(id2[:], []byte("hsdir222222222222222"))
	copy(id3[:], []byte("hsdir333333333333333"))

	cons := &Consensus{
		Routers: []*RouterStatus{
			{Nickname: "HSDir1", Identity: id1, Flags: map[string]bool{"HSDir": true, "Running": true, "Valid": true}},
			{Nickname: "HSDir2", Identity: id2, Flags: map[string]bool{"HSDir": true, "Running": true, "Valid": true}},
			{Nickname: "HSDir3", Identity: id3, Flags: map[string]bool{"HSDir": true, "Running": true, "Valid": true}},
		},
	}

	var descID [32]byte
	copy(descID[:], []byte("target-desc-id-0123456789abcdef"))

	responsible := FindResponsibleHSDirs(cons, descID, 1000, 3)
	if len(responsible) != 3 {
		t.Fatalf("expected 3 responsible HSDir nodes, got %d", len(responsible))
	}
}

func TestBuildIntroduce1Payload(t *testing.T) {
	cookie := [20]byte{1, 2, 3, 4, 5}
	rpSpec := BuildLinkSpecifierIPv4([4]byte{192, 0, 2, 1}, 9001)
	clientEph := [32]byte{9, 9, 9}

	payload := BuildIntroduce1Payload(cookie, [][]byte{rpSpec}, clientEph)
	if len(payload) != 20+1+len(rpSpec)+32 {
		t.Fatalf("unexpected payload length: %d", len(payload))
	}
}

func TestDeriveHSNtorKeys(t *testing.T) {
	clientPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ecdh generate failed: %v", err)
	}
	serverPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ecdh generate server failed: %v", err)
	}

	var servicePub [32]byte
	var subcred [32]byte
	copy(servicePub[:], []byte("service-pubkey-0123456789abcdef"))
	copy(subcred[:], []byte("subcredential-0123456789abcdef0"))

	keys, err := DeriveHSNtorKeys(clientPriv, serverPriv.PublicKey().Bytes(), servicePub, subcred)
	if err != nil {
		t.Fatalf("DeriveHSNtorKeys failed: %v", err)
	}
	if len(keys.Df) != 20 || len(keys.Db) != 20 || len(keys.Kf) != 16 || len(keys.Kb) != 16 {
		t.Fatalf("unexpected key material lengths: %+v", keys)
	}
}

func TestDescriptorLayerEncryptionAndDecryption(t *testing.T) {
	var subcred [32]byte
	copy(subcred[:], []byte("subcredential-test-123456789012"))

	plaintext := []byte("introduction-point test-ip-1\nenc-key ntor AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n")
	salt := []byte("1234567890123456")

	// Derive keys
	keyMaterial := hkdfSHA256(subcred[:], salt, []byte("hsdir-encrypted-data"), 64)
	encKey := keyMaterial[:32]
	macKey := keyMaterial[32:64]

	// Encrypt plaintext
	block, err := aes.NewCipher(encKey)
	if err != nil {
		t.Fatalf("aes cipher failed: %v", err)
	}
	ciphertext := make([]byte, len(plaintext))
	stream := cipher.NewCTR(block, make([]byte, aes.BlockSize))
	stream.XORKeyStream(ciphertext, plaintext)

	// Compute MAC
	macHasher := hmac.New(sha256.New, macKey)
	macHasher.Write(salt)
	macHasher.Write(ciphertext)
	mac := macHasher.Sum(nil)

	// Package layer: salt (16) || ciphertext || MAC (32)
	layer := append([]byte(nil), salt...)
	layer = append(layer, ciphertext...)
	layer = append(layer, mac...)

	decrypted, err := DecryptDescriptorLayer(layer, subcred, "hsdir-encrypted-data")
	if err != nil {
		t.Fatalf("DecryptDescriptorLayer failed: %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Fatalf("expected decrypted plaintext %q, got %q", string(plaintext), string(decrypted))
	}
}
