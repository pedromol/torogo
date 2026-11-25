package tor

import (
	"encoding/binary"
	"fmt"
	"io"
)

const (
	CellBodyLen  = 509
	RelayHdrLen  = 11
	MaxRelayData = CellBodyLen - RelayHdrLen
)

const (
	CmdPadding       = 0
	CmdCreate        = 1
	CmdCreated       = 2
	CmdRelay         = 3
	CmdDestroy       = 4
	CmdCreateFast    = 5
	CmdCreatedFast   = 6
	CmdVersions      = 7
	CmdNetinfo       = 8
	CmdRelayEarly    = 9
	CmdCreate2       = 10
	CmdCreated2      = 11
	CmdVPadding      = 128
	CmdCerts         = 129
	CmdAuthChallenge = 130
	CmdAuthenticate  = 131
)

const (
	RelayBegin     = 1
	RelayData      = 2
	RelayEnd       = 3
	RelayConnected = 4
	RelaySendme    = 5
	RelayExtend    = 6
	RelayExtended  = 7
	RelayTruncate  = 8
	RelayTruncated = 9
	RelayDrop      = 10
	RelayResolve   = 11
	RelayResolved  = 12
	RelayBeginDir  = 13
	RelayExtend2   = 14
	RelayExtended2 = 15

	// Onion / Rendezvous relay commands (tor-spec.txt §3)
	RelayEstablishIntro        = 32
	RelayEstablishRendezvous   = 33
	RelayIntroduce1            = 34
	RelayIntroduce2            = 35
	RelayRendezvous1           = 36
	RelayRendezvous2           = 37
	RelayIntroEstablished      = 38
	RelayRendezvousEstablished = 39
	RelayIntroduceAck          = 40
)

type Cell struct {
	CircID  uint32
	Command byte
	Body    []byte
}

func isVariableCell(cmd byte) bool {
	switch cmd {
	case CmdVersions, CmdVPadding, CmdCerts, CmdAuthChallenge, CmdAuthenticate:
		return true
	default:
		return false
	}
}

func readVersionsCell(r io.Reader) ([]uint16, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	if binary.BigEndian.Uint16(hdr[0:2]) != 0 {
		return nil, fmt.Errorf("tor: VERSIONS with nonzero circid")
	}
	if hdr[2] != CmdVersions {
		return nil, fmt.Errorf("tor: expected VERSIONS, got command %d", hdr[2])
	}
	n := int(binary.BigEndian.Uint16(hdr[3:5]))
	if n%2 != 0 {
		return nil, fmt.Errorf("tor: odd VERSIONS length %d", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	versions := make([]uint16, n/2)
	for i := range versions {
		versions[i] = binary.BigEndian.Uint16(buf[i*2:])
	}
	return versions, nil
}

func writeVersionsCell(w io.Writer, versions []uint16) error {
	buf := make([]byte, 5+2*len(versions))
	binary.BigEndian.PutUint16(buf[0:2], 0)
	buf[2] = CmdVersions
	binary.BigEndian.PutUint16(buf[3:5], uint16(2*len(versions)))
	for i, v := range versions {
		binary.BigEndian.PutUint16(buf[5+i*2:], v)
	}
	_, err := w.Write(buf)
	return err
}

func readCell(r io.Reader) (*Cell, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	circID := binary.BigEndian.Uint32(hdr[0:4])
	cmd := hdr[4]
	if isVariableCell(cmd) {
		var l [2]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return nil, err
		}
		n := int(binary.BigEndian.Uint16(l[:]))
		body := make([]byte, n)
		if _, err := io.ReadFull(r, body); err != nil {
			return nil, err
		}
		return &Cell{CircID: circID, Command: cmd, Body: body}, nil
	}
	body := make([]byte, CellBodyLen)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	return &Cell{CircID: circID, Command: cmd, Body: body}, nil
}

func writeCell(w io.Writer, circID uint32, cmd byte, body []byte) error {
	if isVariableCell(cmd) {
		buf := make([]byte, 7+len(body))
		binary.BigEndian.PutUint32(buf[0:4], circID)
		buf[4] = cmd
		binary.BigEndian.PutUint16(buf[5:7], uint16(len(body)))
		copy(buf[7:], body)
		_, err := w.Write(buf)
		return err
	}
	if len(body) > CellBodyLen {
		return fmt.Errorf("tor: fixed cell body too long: %d", len(body))
	}
	buf := make([]byte, 5+CellBodyLen)
	binary.BigEndian.PutUint32(buf[0:4], circID)
	buf[4] = cmd
	copy(buf[5:], body)
	_, err := w.Write(buf)
	return err
}
