package tor

import (
	"bytes"
	"crypto/rand"
	"crypto/sha3"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

const (
	OnionV3Version      = 0x03
	OnionV3KeyLen       = 32
	OnionV3ChecksumLen  = 2
	OnionV3RawLen       = OnionV3KeyLen + OnionV3ChecksumLen + 1 // 35 bytes
	OnionV3StringLen    = 56                                    // 56 base32 chars
	OnionV3Suffix       = ".onion"
	TimePeriodLengthSec = 86400 // 24 hours
	TimePeriodOffsetSec = 12 * 3600
)

// OnionV3Address represents a parsed Tor v3 hidden service address.
type OnionV3Address struct {
	PublicKey [OnionV3KeyLen]byte
	Checksum  [OnionV3ChecksumLen]byte
	Version   byte
	Address   string
}

// CalculateOnionChecksum computes the 2-byte SHA3-256 checksum per rend-spec-v3.txt Appendix C.
func CalculateOnionChecksum(pubkey []byte, version byte) [OnionV3ChecksumLen]byte {
	h := sha3.New256()
	h.Write([]byte(".onion checksum"))
	h.Write(pubkey)
	h.Write([]byte{version})
	sum := h.Sum(nil)
	var cs [OnionV3ChecksumLen]byte
	copy(cs[:], sum[:OnionV3ChecksumLen])
	return cs
}

// ParseOnionV3 parses and verifies a Tor v3 .onion address string.
func ParseOnionV3(addr string) (*OnionV3Address, error) {
	clean := strings.ToLower(strings.TrimSpace(addr))
	clean = strings.TrimSuffix(clean, OnionV3Suffix)

	if len(clean) != OnionV3StringLen {
		return nil, fmt.Errorf("tor: invalid onion v3 address length (%d, expected %d)", len(clean), OnionV3StringLen)
	}

	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(clean))
	if err != nil {
		return nil, fmt.Errorf("tor: invalid base32 in onion address: %w", err)
	}
	if len(raw) != OnionV3RawLen {
		return nil, fmt.Errorf("tor: invalid onion decoded length (%d, expected %d)", len(raw), OnionV3RawLen)
	}

	var pubkey [OnionV3KeyLen]byte
	copy(pubkey[:], raw[:OnionV3KeyLen])

	var checksum [OnionV3ChecksumLen]byte
	copy(checksum[:], raw[OnionV3KeyLen:OnionV3KeyLen+OnionV3ChecksumLen])

	version := raw[34]
	if version != OnionV3Version {
		return nil, fmt.Errorf("tor: unsupported onion version %d (expected %d)", version, OnionV3Version)
	}

	expectedChecksum := CalculateOnionChecksum(pubkey[:], version)
	if !bytes.Equal(checksum[:], expectedChecksum[:]) {
		return nil, fmt.Errorf("tor: invalid onion checksum")
	}

	return &OnionV3Address{
		PublicKey: pubkey,
		Checksum:  checksum,
		Version:   version,
		Address:   clean + OnionV3Suffix,
	}, nil
}

// EncodeOnionV3 generates the 56-character base32 .onion address from a 32-byte Ed25519 public key.
func EncodeOnionV3(pubkey [OnionV3KeyLen]byte) string {
	checksum := CalculateOnionChecksum(pubkey[:], OnionV3Version)
	var raw [OnionV3RawLen]byte
	copy(raw[:32], pubkey[:])
	copy(raw[32:34], checksum[:])
	raw[34] = OnionV3Version

	encoded := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw[:]))
	return encoded + OnionV3Suffix
}

// CalculateTimePeriod calculates the Tor v3 time period number per rend-spec-v3.txt §2.2.1.
func CalculateTimePeriod(t time.Time) uint64 {
	sec := t.UTC().Unix()
	if sec < TimePeriodOffsetSec {
		return 0
	}
	return uint64(sec-TimePeriodOffsetSec) / TimePeriodLengthSec
}

// NewRendezvousCookie generates a cryptographically random 20-byte rendezvous cookie.
func NewRendezvousCookie() ([20]byte, error) {
	var cookie [20]byte
	if _, err := rand.Read(cookie[:]); err != nil {
		return cookie, err
	}
	return cookie, nil
}

// EstablishRendezvous sends RELAY_ESTABLISH_RENDEZVOUS on circuit and awaits RELAY_RENDEZVOUS_ESTABLISHED.
func EstablishRendezvous(circ *Circuit, cookie [20]byte) error {
	if circ == nil || len(circ.hops) == 0 {
		return fmt.Errorf("tor: circuit has no hops")
	}
	exit := len(circ.hops) - 1
	if err := circ.sendRelayCell(exit, CmdRelay, RelayEstablishRendezvous, 0, cookie[:]); err != nil {
		return fmt.Errorf("tor: failed to send ESTABLISH_RENDEZVOUS: %w", err)
	}

	for {
		hop, cmd, _, _, err := circ.recvRelayCell()
		if err != nil {
			return fmt.Errorf("tor: error awaiting RENDEZVOUS_ESTABLISHED: %w", err)
		}
		if hop != exit {
			continue
		}
		switch cmd {
		case RelayRendezvousEstablished:
			return nil
		case RelayEnd:
			return fmt.Errorf("tor: rendezvous rejected by relay")
		}
	}
}

// BuildLinkSpecifierIPv4 constructs a Link Specifier for an IPv4 ORPort.
func BuildLinkSpecifierIPv4(ip [4]byte, port uint16) []byte {
	var b [8]byte
	b[0] = 0 // LSTYPE: TLS-over-TCP, IPv4
	b[1] = 6 // LSLEN: 6 bytes (4-byte IP + 2-byte port)
	copy(b[2:6], ip[:])
	binary.BigEndian.PutUint16(b[6:8], port)
	return b[:]
}

// BuildLinkSpecifierLegacyID constructs a Link Specifier for a 20-byte SHA1 identity fingerprint.
func BuildLinkSpecifierLegacyID(identity [20]byte) []byte {
	var b [22]byte
	b[0] = 2  // LSTYPE: Legacy identity
	b[1] = 20 // LSLEN: 20 bytes
	copy(b[2:22], identity[:])
	return b[:]
}
