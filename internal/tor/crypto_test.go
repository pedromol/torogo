package tor

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"math/big"
	"testing"
)

func TestVerifyRSARaw(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pubKey := &privKey.PublicKey

	msg := []byte("tor consensus test message")
	sum := sha256.Sum256(msg)

	// Build raw PKCS#1 v1.5 padding:
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
	sig := s.FillBytes(make([]byte, k))

	// Verify using verifyRSARaw
	if !verifyRSARaw(pubKey, sum[:], sig) {
		t.Error("verifyRSARaw failed for valid signature")
	}

	// Verify using verifyRSASHA256
	if !verifyRSASHA256(pubKey, msg, sig) {
		t.Error("verifyRSASHA256 failed for valid signature")
	}

	// Corrupt signature
	sig[len(sig)-1] ^= 0x01
	if verifyRSARaw(pubKey, sum[:], sig) {
		t.Error("verifyRSARaw should fail for corrupted signature")
	}
}

func TestVerifyRSASHA1(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	pubKey := &privKey.PublicKey

	msg := []byte("sha1 test")
	sum := sha1.Sum(msg)

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

	c := new(big.Int).SetBytes(em)
	s := new(big.Int).Exp(c, privKey.D, privKey.N)
	sig := s.FillBytes(make([]byte, k))

	if !verifyRSASHA1(pubKey, msg, sig) {
		t.Error("verifyRSASHA1 failed for valid signature")
	}
}
