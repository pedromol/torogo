package tor

import (
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"math/big"
)

const (
	ntorProtoID = "ntor-curve25519-sha256-1"
	ntorMac     = ntorProtoID + ":mac"
	ntorKey     = ntorProtoID + ":key_extract"
	ntorVerify  = ntorProtoID + ":verify"
	ntorExpand  = ntorProtoID + ":key_expand"
)

type HopKeys struct {
	Df []byte
	Db []byte
	Kf []byte
	Kb []byte
}

type NtorClient struct {
	priv *ecdh.PrivateKey
}

func NewNtorClient() (*NtorClient, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &NtorClient{priv: priv}, nil
}

func (n *NtorClient) PublicKey() []byte {
	return n.priv.PublicKey().Bytes()
}

func (n *NtorClient) Process(nodeID, onionKey, serverPub, serverAuth []byte) (*HopKeys, error) {
	if len(nodeID) != 20 {
		return nil, fmt.Errorf("tor: ntor node ID must be 20 bytes, got %d", len(nodeID))
	}
	if len(onionKey) != 32 {
		return nil, fmt.Errorf("tor: ntor onion key must be 32 bytes, got %d", len(onionKey))
	}
	if len(serverPub) != 32 {
		return nil, fmt.Errorf("tor: ntor server public key must be 32 bytes, got %d", len(serverPub))
	}
	if len(serverAuth) != 32 {
		return nil, fmt.Errorf("tor: ntor server auth must be 32 bytes, got %d", len(serverAuth))
	}

	serverPublic, err := ecdh.X25519().NewPublicKey(serverPub)
	if err != nil {
		return nil, fmt.Errorf("tor: invalid ntor server public key: %w", err)
	}
	xy, err := n.priv.ECDH(serverPublic)
	if err != nil {
		return nil, fmt.Errorf("tor: ntor X25519(y) failed: %w", err)
	}
	onionPublic, err := ecdh.X25519().NewPublicKey(onionKey)
	if err != nil {
		return nil, fmt.Errorf("tor: invalid ntor onion key: %w", err)
	}
	xb, err := n.priv.ECDH(onionPublic)
	if err != nil {
		return nil, fmt.Errorf("tor: ntor X25519(b) failed: %w", err)
	}
	clientPub := n.priv.PublicKey().Bytes()

	secretInput := make([]byte, 0, 32+32+20+32+32+32+len(ntorProtoID))
	secretInput = append(secretInput, xy...)
	secretInput = append(secretInput, xb...)
	secretInput = append(secretInput, nodeID...)
	secretInput = append(secretInput, onionKey...)
	secretInput = append(secretInput, clientPub...)
	secretInput = append(secretInput, serverPub...)
	secretInput = append(secretInput, []byte(ntorProtoID)...)

	verify := hmacSHA256([]byte(ntorVerify), secretInput)

	authInput := make([]byte, 0, 32+20+32+32+32+len(ntorProtoID)+6)
	authInput = append(authInput, verify...)
	authInput = append(authInput, nodeID...)
	authInput = append(authInput, onionKey...)
	authInput = append(authInput, serverPub...)
	authInput = append(authInput, clientPub...)
	authInput = append(authInput, []byte(ntorProtoID)...)
	authInput = append(authInput, []byte("Server")...)

	expectedAuth := hmacSHA256([]byte(ntorMac), authInput)
	if !hmac.Equal(expectedAuth, serverAuth) {
		return nil, fmt.Errorf("tor: ntor server authentication failed")
	}

	km := hkdfSHA256(secretInput, []byte(ntorKey), []byte(ntorExpand), 92)
	return &HopKeys{
		Df: append([]byte(nil), km[0:20]...),
		Db: append([]byte(nil), km[20:40]...),
		Kf: append([]byte(nil), km[40:56]...),
		Kb: append([]byte(nil), km[56:72]...),
	}, nil
}

func hmacSHA256(key, msg []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(msg)
	return h.Sum(nil)
}

func hkdfSHA256(ikm, salt, info []byte, length int) []byte {
	if len(salt) == 0 {
		salt = make([]byte, sha256.Size)
	}
	prk := hmacSHA256(salt, ikm)
	out := make([]byte, 0, length)
	var t []byte
	for counter := byte(1); len(out) < length; counter++ {
		h := hmac.New(sha256.New, prk)
		h.Write(t)
		h.Write(info)
		h.Write([]byte{counter})
		t = h.Sum(nil)
		out = append(out, t...)
	}
	return out[:length]
}

// verifyRSARaw verifies a Tor-style RSA PKCS#1 v1.5 signature. Tor signs the
// digest directly, without the PKCS#1 DigestInfo prefix used by crypto/rsa.
func verifyRSARaw(pub *rsa.PublicKey, digest, sig []byte) bool {
	if pub == nil || pub.N == nil || pub.N.Sign() <= 0 || pub.E < 2 {
		return false
	}
	k := pub.Size()
	if len(sig) != k || len(digest) > k-11 {
		return false
	}
	m := new(big.Int).SetBytes(sig)
	m.Exp(m, big.NewInt(int64(pub.E)), pub.N)
	em := m.FillBytes(make([]byte, k))

	want := make([]byte, k)
	want[0] = 0
	want[1] = 1
	psLen := k - 3 - len(digest)
	for i := 0; i < psLen; i++ {
		want[2+i] = 0xff
	}
	want[2+psLen] = 0
	copy(want[k-len(digest):], digest)
	return hmac.Equal(em, want)
}

func verifyRSASHA1(pub *rsa.PublicKey, msg, sig []byte) bool {
	sum := sha1.Sum(msg)
	return verifyRSARaw(pub, sum[:], sig)
}

func verifyRSASHA256(pub *rsa.PublicKey, msg, sig []byte) bool {
	sum := sha256.Sum256(msg)
	return verifyRSARaw(pub, sum[:], sig)
}
