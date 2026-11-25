package tor

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha3"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"sort"
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

// DeriveBlindedKey derives the 32-byte blinded public key per rend-spec-v3.txt §2.2.1.
func DeriveBlindedKey(pubkey [32]byte, timePeriod uint64) [32]byte {
	h := sha3.New256()
	h.Write([]byte("Derive blinded public key"))
	h.Write(pubkey[:])
	var tpBytes [8]byte
	binary.BigEndian.PutUint64(tpBytes[:], timePeriod)
	h.Write(tpBytes[:])
	var blinded [32]byte
	copy(blinded[:], h.Sum(nil))
	return blinded
}

// DeriveSubcredential computes the subcredential for descriptor encryption per rend-spec-v3.txt §2.2.2.
func DeriveSubcredential(pubkey [32]byte, blindedKey [32]byte) [32]byte {
	h := sha3.New256()
	h.Write([]byte("subcred"))
	h.Write(pubkey[:])
	h.Write(blindedKey[:])
	var subcred [32]byte
	copy(subcred[:], h.Sum(nil))
	return subcred
}

// CalculateHSDirIndex computes an HSDir relay's position on the hash ring per rend-spec-v3.txt §2.2.3.
func CalculateHSDirIndex(identity [20]byte, timePeriod uint64) [32]byte {
	h := sha3.New256()
	h.Write([]byte("node-idx"))
	h.Write(identity[:])
	var tpBytes [8]byte
	binary.BigEndian.PutUint64(tpBytes[:], timePeriod)
	h.Write(tpBytes[:])
	var idx [32]byte
	copy(idx[:], h.Sum(nil))
	return idx
}

// CalculateDescriptorID calculates the descriptor identifier index for a replica per rend-spec-v3.txt §2.2.3.
func CalculateDescriptorID(blindedKey [32]byte, timePeriod uint64, replica uint8) [32]byte {
	h := sha3.New256()
	h.Write([]byte("store-at-idx"))
	h.Write(blindedKey[:])
	h.Write([]byte{replica})
	var tpBytes [8]byte
	binary.BigEndian.PutUint64(tpBytes[:], timePeriod)
	h.Write(tpBytes[:])
	var descID [32]byte
	copy(descID[:], h.Sum(nil))
	return descID
}

type hsdirNode struct {
	router *RouterStatus
	index  [32]byte
}

// FindResponsibleHSDirs finds the HSDir relays in consensus responsible for storing a descriptor.
func FindResponsibleHSDirs(cons *Consensus, descID [32]byte, timePeriod uint64, count int) []*RouterStatus {
	if cons == nil || count <= 0 {
		return nil
	}
	var ring []hsdirNode
	for _, rs := range cons.Routers {
		if rs.HasFlag("HSDir") && rs.HasFlag("Running") && rs.HasFlag("Valid") {
			idx := CalculateHSDirIndex(rs.Identity, timePeriod)
			ring = append(ring, hsdirNode{router: rs, index: idx})
		}
	}
	if len(ring) == 0 {
		return nil
	}

	sort.Slice(ring, func(i, j int) bool {
		return bytes.Compare(ring[i].index[:], ring[j].index[:]) < 0
	})

	// Find the first node whose index >= descID
	startIdx := 0
	for i, node := range ring {
		if bytes.Compare(node.index[:], descID[:]) >= 0 {
			startIdx = i
			break
		}
	}

	if count > len(ring) {
		count = len(ring)
	}
	out := make([]*RouterStatus, 0, count)
	for i := 0; i < count; i++ {
		idx := (startIdx + i) % len(ring)
		out = append(out, ring[idx].router)
	}
	return out
}

// IntroPoint represents a Tor v3 Onion Service introduction point.
type IntroPoint struct {
	AuthKey        [32]byte
	EncKey         [32]byte
	LinkSpecifiers [][]byte
}

// BuildIntroduce1Payload constructs the plaintext payload for RELAY_INTRODUCE1 per rend-spec-v3.txt §3.3.
func BuildIntroduce1Payload(cookie [20]byte, rpLinkSpecifiers [][]byte, clientEphemeralPub [32]byte) []byte {
	var payload []byte
	payload = append(payload, cookie[:]...)
	payload = append(payload, byte(len(rpLinkSpecifiers)))
	for _, ls := range rpLinkSpecifiers {
		payload = append(payload, ls...)
	}
	payload = append(payload, clientEphemeralPub[:]...)
	return payload
}

// DeriveHSNtorKeys derives circuit crypto keys for the hidden service rendezvous hop.
func DeriveHSNtorKeys(clientPriv *ecdh.PrivateKey, serverPubBytes []byte, servicePub [32]byte, subcred [32]byte) (*HopKeys, error) {
	serverPub, err := ecdh.X25519().NewPublicKey(serverPubBytes)
	if err != nil {
		return nil, fmt.Errorf("tor: invalid server public key for hs-ntor: %w", err)
	}
	sharedSecret, err := clientPriv.ECDH(serverPub)
	if err != nil {
		return nil, fmt.Errorf("tor: ecdh failed for hs-ntor: %w", err)
	}

	// HKDF-SHA256 derivation
	keyMaterial := hkdfSHA256(sharedSecret, subcred[:], []byte("hs-ntor-keys"), 72)
	return &HopKeys{
		Df: keyMaterial[0:20],
		Db: keyMaterial[20:40],
		Kf: keyMaterial[40:56],
		Kb: keyMaterial[56:72],
	}, nil
}
