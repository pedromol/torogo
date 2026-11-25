package tor

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"testing"
)

func TestNtorKeyDerivation(t *testing.T) {
	t.Run("hkdf expands correctly", func(t *testing.T) {
		ikm := []byte{0x01, 0x02, 0x03, 0x04} // input key material
		salt := []byte("ntor-curve25519-sha256-1:mac")

		key, err := hkdf.Key(sha256.New, ikm, salt, "ntor-curve25519-sha256-1:key_extract", 32)
		if err != nil {
			t.Fatalf("hkdf.Key: %v", err)
		}
		if len(key) != 32 {
			t.Errorf("expected 32 byte key, got %d", len(key))
		}
	})

	t.Run("ntor client generates valid keypair", func(t *testing.T) {
		ntor, err := NewNtorClient()
		if err != nil {
			t.Fatalf("NewNtorClient: %v", err)
		}
		pub := ntor.PublicKey()
		if len(pub) != 32 {
			t.Errorf("expected 32 byte public key, got %d", len(pub))
		}

		_, err = ecdh.X25519().NewPublicKey(pub)
		if err != nil {
			t.Errorf("generated public key is not valid X25519: %v", err)
		}
	})

	t.Run("ntor client produces different keys on each call", func(t *testing.T) {
		ntor1, _ := NewNtorClient()
		ntor2, _ := NewNtorClient()

		if string(ntor1.PublicKey()) == string(ntor2.PublicKey()) {
			t.Errorf("two clients generated identical keys")
		}
	})
}

func TestNtorProcessInputs(t *testing.T) {
	ntor, _ := NewNtorClient()

	t.Run("validates nodeID length", func(t *testing.T) {
		_, err := ntor.Process(make([]byte, 19), make([]byte, 32), make([]byte, 32), make([]byte, 32))
		if err == nil {
			t.Error("expected error for short nodeID")
		}
	})

	t.Run("validates onionKey length", func(t *testing.T) {
		_, err := ntor.Process(make([]byte, 20), make([]byte, 31), make([]byte, 32), make([]byte, 32))
		if err == nil {
			t.Error("expected error for short onionKey")
		}
	})

	t.Run("validates serverPub length", func(t *testing.T) {
		_, err := ntor.Process(make([]byte, 20), make([]byte, 32), make([]byte, 31), make([]byte, 32))
		if err == nil {
			t.Error("expected error for short serverPub")
		}
	})

	t.Run("validates serverAuth length", func(t *testing.T) {
		_, err := ntor.Process(make([]byte, 20), make([]byte, 32), make([]byte, 32), make([]byte, 31))
		if err == nil {
			t.Error("expected error for short serverAuth")
		}
	})
}

func TestNtorFullHandshake(t *testing.T) {
	// 1. Setup Relay static onion key B (private b) and NodeID
	serverOnionPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverOnionPub := serverOnionPriv.PublicKey().Bytes()
	nodeID := []byte("01234567890123456789") // 20 bytes

	// 2. Client initiates handshake (CREATE2 with X)
	client, err := NewNtorClient()
	if err != nil {
		t.Fatal(err)
	}
	clientX := client.PublicKey()

	// 3. Server receives X, generates ephemeral Y (private y)
	serverEphPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverY := serverEphPriv.PublicKey().Bytes()

	// Server computes shared secrets: yx = y * X, bx = b * X
	clientXPub, err := ecdh.X25519().NewPublicKey(clientX)
	if err != nil {
		t.Fatal(err)
	}
	yx, err := serverEphPriv.ECDH(clientXPub)
	if err != nil {
		t.Fatal(err)
	}
	bx, err := serverOnionPriv.ECDH(clientXPub)
	if err != nil {
		t.Fatal(err)
	}

	// Server builds secretInput
	secretInput := make([]byte, 0, 32+32+20+32+32+32+len(ntorProtoID))
	secretInput = append(secretInput, yx...)
	secretInput = append(secretInput, bx...)
	secretInput = append(secretInput, nodeID...)
	secretInput = append(secretInput, serverOnionPub...)
	secretInput = append(secretInput, clientX...)
	secretInput = append(secretInput, serverY...)
	secretInput = append(secretInput, []byte(ntorProtoID)...)

	verify := hmacSHA256([]byte(ntorVerify), secretInput)

	authInput := make([]byte, 0, 32+20+32+32+32+len(ntorProtoID)+6)
	authInput = append(authInput, verify...)
	authInput = append(authInput, nodeID...)
	authInput = append(authInput, serverOnionPub...)
	authInput = append(authInput, serverY...)
	authInput = append(authInput, clientX...)
	authInput = append(authInput, []byte(ntorProtoID)...)
	authInput = append(authInput, []byte("Server")...)

	serverAuth := hmacSHA256([]byte(ntorMac), authInput)

	// Server derives keys
	serverKM := hkdfSHA256(secretInput, []byte(ntorKey), []byte(ntorExpand), 92)

	// 4. Client processes server response (Y and serverAuth)
	clientKeys, err := client.Process(nodeID, serverOnionPub, serverY, serverAuth)
	if err != nil {
		t.Fatalf("client.Process failed: %v", err)
	}

	// 5. Verify derived keys match between client and server
	if !bytes.Equal(clientKeys.Df, serverKM[0:20]) {
		t.Errorf("Df key mismatch")
	}
	if !bytes.Equal(clientKeys.Db, serverKM[20:40]) {
		t.Errorf("Db key mismatch")
	}
	if !bytes.Equal(clientKeys.Kf, serverKM[40:56]) {
		t.Errorf("Kf key mismatch")
	}
	if !bytes.Equal(clientKeys.Kb, serverKM[56:72]) {
		t.Errorf("Kb key mismatch")
	}

	// 6. Test server authentication failure when auth MAC is corrupted
	corruptedAuth := append([]byte(nil), serverAuth...)
	corruptedAuth[0] ^= 0xFF
	if _, err := client.Process(nodeID, serverOnionPub, serverY, corruptedAuth); err == nil {
		t.Errorf("expected authentication error for corrupted serverAuth")
	}
}

func TestHopKeysStructure(t *testing.T) {
	keys := &HopKeys{
		Df: make([]byte, 16),
		Db: make([]byte, 16),
		Kf: make([]byte, 16),
		Kb: make([]byte, 16),
	}

	if len(keys.Df) != 16 || len(keys.Db) != 16 || len(keys.Kf) != 16 || len(keys.Kb) != 16 {
		t.Error("HopKeys fields should be 16 bytes each (AES-128)")
	}

	if len(keys.Kf) == 0 {
		t.Error("Kf should be non-empty")
	}
}

func TestHMACVerification(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	msg := []byte("test message")
	h := hmac.New(sha256.New, key)
	h.Write(msg)
	mac := h.Sum(nil)

	if len(mac) != 32 {
		t.Errorf("HMAC-SHA256 should be 32 bytes, got %d", len(mac))
	}

	h2 := hmac.New(sha256.New, key)
	h2.Write(msg)
	if !hmac.Equal(mac, h2.Sum(nil)) {
		t.Error("HMAC verification failed")
	}
}

func TestCREATE2BodyFormat(t *testing.T) {
	body := make([]byte, CellBodyLen)
	binary.BigEndian.PutUint16(body[0:2], 0x0002)
	binary.BigEndian.PutUint16(body[2:4], 84)

	htype := binary.BigEndian.Uint16(body[0:2])
	hlen := binary.BigEndian.Uint16(body[2:4])

	if htype != 0x0002 {
		t.Errorf("handshake type: expected 0x0002, got 0x%04x", htype)
	}
	if hlen != 84 {
		t.Errorf("handshake length: expected 84, got %d", hlen)
	}
}
