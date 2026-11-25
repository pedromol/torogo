package tor

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding"
	"encoding/binary"
	"fmt"
	"hash"
	"net"
	"strings"
	"sync"
)

type Hop struct {
	Router *RouterStatus
	MD     *Microdesc

	fwd       cipher.Stream
	bwd       cipher.Stream
	fwdDigest hash.Hash
	bwdDigest hash.Hash
}

const (
	CircWindowInit      = 1000
	CircWindowIncrement = 100
	CircWindowThreshold = CircWindowInit - CircWindowIncrement // 900

	StreamWindowInit      = 500
	StreamWindowIncrement = 50
	StreamWindowThreshold = StreamWindowInit - StreamWindowIncrement // 450
)

type Circuit struct {
	link          *Link
	circID        uint32
	hops          []*Hop
	sendMu        sync.Mutex
	recvMu        sync.Mutex
	packageWindow int
	deliverWindow int
}

func NewCircuit(link *Link, rs *RouterStatus, md *Microdesc) (*Circuit, error) {
	if link == nil || rs == nil || md == nil {
		return nil, fmt.Errorf("tor: nil circuit input")
	}
	ntor, err := NewNtorClient()
	if err != nil {
		return nil, err
	}
	circID := randomCircID()
	body := make([]byte, CellBodyLen)
	binary.BigEndian.PutUint16(body[0:2], 0x0002)
	binary.BigEndian.PutUint16(body[2:4], 84)
	copy(body[4:24], rs.Identity[:])
	copy(body[24:56], md.NtorOnionKey)
	copy(body[56:88], ntor.PublicKey())
	c := &Circuit{
		link:          link,
		circID:        circID,
		packageWindow: CircWindowInit,
		deliverWindow: CircWindowInit,
	}
	if err := link.sendCell(circID, CmdCreate2, body); err != nil {
		return nil, err
	}
	for {
		cell, err := link.recvCell()
		if err != nil {
			return nil, err
		}
		if cell.CircID != circID {
			continue
		}
		switch cell.Command {
		case CmdCreated2:
			hlen, hdata, err := parseCreated2(cell.Body)
			if err != nil {
				return nil, err
			}
			if hlen != 64 || len(hdata) != 64 {
				return nil, fmt.Errorf("tor: unexpected CREATED2 parameters")
			}
			keys, err := ntor.Process(rs.Identity[:], md.NtorOnionKey, hdata[:32], hdata[32:64])
			if err != nil {
				return nil, err
			}
			hop, err := newHop(rs, md, keys)
			if err != nil {
				return nil, err
			}
			c.hops = append(c.hops, hop)
			return c, nil
		case CmdDestroy:
			return nil, fmt.Errorf("tor: guard destroyed circuit during CREATE2")
		case CmdPadding, CmdVPadding:
			continue
		}
	}
}

func (c *Circuit) Extend(rs *RouterStatus, md *Microdesc) error {
	if c == nil || len(c.hops) == 0 {
		return fmt.Errorf("tor: circuit has no hops")
	}
	if rs == nil || md == nil {
		return fmt.Errorf("tor: nil extend input")
	}
	ntor, err := NewNtorClient()
	if err != nil {
		return err
	}
	ip4 := rs.IP.To4()
	if ip4 == nil {
		return fmt.Errorf("tor: target relay has no IPv4 address")
	}
	var payload []byte
	payload = append(payload, 3)
	payload = append(payload, 0, 6)
	payload = append(payload, ip4...)
	payload = append(payload, byte(rs.ORPort>>8), byte(rs.ORPort))
	payload = append(payload, 2, 20)
	payload = append(payload, rs.Identity[:]...)
	payload = append(payload, 3, 32)
	payload = append(payload, md.Ed25519ID...)
	payload = append(payload, 0, 2, 0, 84)
	payload = append(payload, rs.Identity[:]...)
	payload = append(payload, md.NtorOnionKey...)
	payload = append(payload, ntor.PublicKey()...)

	last := len(c.hops) - 1
	if err := c.sendRelayCell(last, CmdRelayEarly, RelayExtend2, 0, payload); err != nil {
		return err
	}
	for {
		hop, cmd, _, data, err := c.recvRelayCell()
		if err != nil {
			return err
		}
		if hop != last {
			continue
		}
		switch cmd {
		case RelayExtended2:
			if len(data) < 2 {
				return fmt.Errorf("tor: short EXTENDED2")
			}
			hlen := int(binary.BigEndian.Uint16(data[0:2]))
			if hlen != 64 || len(data) < 2+hlen {
				return fmt.Errorf("tor: bad EXTENDED2 length")
			}
			hdata := data[2 : 2+hlen]
			keys, err := ntor.Process(rs.Identity[:], md.NtorOnionKey, hdata[:32], hdata[32:64])
			if err != nil {
				return err
			}
			newHop, err := newHop(rs, md, keys)
			if err != nil {
				return err
			}
			c.hops = append(c.hops, newHop)
			return nil
		case RelayTruncated:
			return fmt.Errorf("tor: circuit truncated during EXTEND2")
		case RelayEnd:
			if len(data) > 0 {
				return fmt.Errorf("tor: stream error during EXTEND2: reason %d", data[0])
			}
			return fmt.Errorf("tor: stream error during EXTEND2")
		}
	}
}

func newHop(rs *RouterStatus, md *Microdesc, keys *HopKeys) (*Hop, error) {
	fwdBlock, err := aes.NewCipher(keys.Kf)
	if err != nil {
		return nil, err
	}
	bwdBlock, err := aes.NewCipher(keys.Kb)
	if err != nil {
		return nil, err
	}
	df := sha1.New()
	df.Write(keys.Df)
	db := sha1.New()
	db.Write(keys.Db)
	return &Hop{
		Router:    rs,
		MD:        md,
		fwd:       cipher.NewCTR(fwdBlock, make([]byte, aes.BlockSize)),
		bwd:       cipher.NewCTR(bwdBlock, make([]byte, aes.BlockSize)),
		fwdDigest: df,
		bwdDigest: db,
	}, nil
}

func (c *Circuit) sendRelayCell(hopIndex int, cellCmd, relayCmd byte, streamID uint16, data []byte) error {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()

	if hopIndex < 0 || hopIndex >= len(c.hops) {
		return fmt.Errorf("tor: bad hop index %d", hopIndex)
	}
	body, err := makeRelayBody(relayCmd, streamID, data)
	if err != nil {
		return err
	}
	hop := c.hops[hopIndex]
	hop.fwdDigest.Write(body)
	digest := hop.fwdDigest.Sum(nil)
	copy(body[5:9], digest[:4])
	for i := 0; i <= hopIndex; i++ {
		c.hops[i].fwd.XORKeyStream(body, body)
	}
	if cellCmd == CmdRelay && relayCmd == RelayData {
		c.packageWindow--
	}
	return c.link.sendCell(c.circID, cellCmd, body)
}

func (c *Circuit) recvRelayCell() (int, byte, uint16, []byte, error) {
	c.recvMu.Lock()
	defer c.recvMu.Unlock()

	for {
		cell, err := c.link.recvCell()
		if err != nil {
			return -1, 0, 0, nil, err
		}
		if cell.CircID != c.circID {
			continue
		}
		switch cell.Command {
		case CmdDestroy:
			return -1, 0, 0, nil, fmt.Errorf("tor: circuit destroyed")
		case CmdRelay, CmdRelayEarly:
		default:
			continue
		}
		body := cell.Body
		for i, hop := range c.hops {
			hop.bwd.XORKeyStream(body, body)
			if binary.BigEndian.Uint16(body[1:3]) != 0 {
				continue
			}
			sig := append([]byte(nil), body[5:9]...)
			tmpBody := append([]byte(nil), body...)
			copy(tmpBody[5:9], []byte{0, 0, 0, 0})
			tmpHash := cloneSHA1(hop.bwdDigest)
			tmpHash.Write(tmpBody)
			sum := tmpHash.Sum(nil)
			if hmac.Equal(sum[:4], sig) {
				hop.bwdDigest = tmpHash
				l := int(binary.BigEndian.Uint16(body[9:11]))
				if l > MaxRelayData {
					return -1, 0, 0, nil, fmt.Errorf("tor: relay payload too long")
				}
				data := append([]byte(nil), body[11:11+l]...)
				cmd := body[0]
				sid := binary.BigEndian.Uint16(body[3:5])

				if cmd == RelayData {
					c.deliverWindow--
					if c.deliverWindow <= CircWindowThreshold {
						_ = c.sendRelayCell(i, CmdRelay, RelaySendme, 0, nil)
						c.deliverWindow += CircWindowIncrement
					}
				} else if cmd == RelaySendme && sid == 0 {
					c.packageWindow += CircWindowIncrement
				}

				return i, cmd, sid, data, nil
			}
		}
	}
}

func parseCreated2(body []byte) (int, []byte, error) {
	if len(body) < 2 {
		return 0, nil, fmt.Errorf("tor: short CREATED2")
	}
	hlen := int(binary.BigEndian.Uint16(body[0:2]))
	if hlen < 0 || 2+hlen > len(body) {
		return 0, nil, fmt.Errorf("tor: bad CREATED2 length")
	}
	return hlen, body[2 : 2+hlen], nil
}

func makeRelayBody(cmd byte, streamID uint16, data []byte) ([]byte, error) {
	if len(data) > MaxRelayData {
		return nil, fmt.Errorf("tor: relay data too long: %d", len(data))
	}
	body := make([]byte, CellBodyLen)
	body[0] = cmd
	binary.BigEndian.PutUint16(body[3:5], streamID)
	binary.BigEndian.PutUint16(body[9:11], uint16(len(data)))
	copy(body[11:], data)
	pad := body[11+len(data):]
	if len(pad) > 4 {
		_, _ = rand.Read(pad[4:])
	}
	return body, nil
}

func cloneSHA1(h hash.Hash) hash.Hash {
	m, err := h.(encoding.BinaryMarshaler).MarshalBinary()
	if err != nil {
		panic(err)
	}
	clone := sha1.New()
	if err := clone.(encoding.BinaryUnmarshaler).UnmarshalBinary(m); err != nil {
		panic(err)
	}
	return clone
}

func randomCircID() uint32 {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	id := binary.BigEndian.Uint32(b[:]) | 0x80000000
	if id == 0 {
		id = 0x80000001
	}
	return id
}

func (c *Circuit) Close() error {
	if c == nil || c.link == nil {
		return nil
	}
	return c.link.Close()
}

// SendPadding sends a fixed-size padding cell (CmdPadding) on the circuit to keep the connection alive.
func (c *Circuit) SendPadding() error {
	pad := make([]byte, CellBodyLen)
	return c.link.sendCell(c.circID, CmdPadding, pad)
}

// Resolve performs remote DNS resolution over the Tor circuit per tor-spec.txt §6.4.
func (c *Circuit) Resolve(host string) ([]net.IP, error) {
	if c == nil || len(c.hops) == 0 {
		return nil, fmt.Errorf("tor: circuit has no hops")
	}
	id := randomStreamID()
	payload := []byte(strings.ToLower(host) + "\x00")
	exit := len(c.hops) - 1

	if err := c.sendRelayCell(exit, CmdRelay, RelayResolve, id, payload); err != nil {
		return nil, err
	}

	for {
		hop, cmd, sid, data, err := c.recvRelayCell()
		if err != nil {
			return nil, err
		}
		if hop != exit || sid != id {
			continue
		}
		switch cmd {
		case RelayResolved:
			return parseResolvedPayload(data)
		case RelayEnd:
			return nil, fmt.Errorf("tor: resolve failed: %w", endReasonError(data))
		}
	}
}

func parseResolvedPayload(data []byte) ([]net.IP, error) {
	var ips []net.IP
	idx := 0
	for idx < len(data) {
		if idx+2 > len(data) {
			break
		}
		ansType := data[idx]
		ansLen := int(data[idx+1])
		idx += 2
		if idx+ansLen > len(data) {
			break
		}
		val := data[idx : idx+ansLen]
		idx += ansLen
		if idx+4 <= len(data) {
			idx += 4 // Discard TTL
		}

		switch ansType {
		case 0x04: // IPv4
			if len(val) == 4 {
				ip := make(net.IP, 4)
				copy(ip, val)
				ips = append(ips, ip)
			}
		case 0x06: // IPv6
			if len(val) == 16 {
				ip := make(net.IP, 16)
				copy(ip, val)
				ips = append(ips, ip)
			}
		case 0xF0: // Transient error
			return nil, fmt.Errorf("tor: transient DNS resolve error")
		case 0xF1: // Non-transient error
			return nil, fmt.Errorf("tor: host not found (DNS error)")
		}
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("tor: no IP addresses returned in RELAY_RESOLVED")
	}
	return ips, nil
}
