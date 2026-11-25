package tor

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

type Stream struct {
	circuit       *Circuit
	id            uint16
	mu            sync.Mutex
	pending       []byte
	closed        bool
	packageWindow int
	deliverWindow int
}

func (c *Circuit) OpenStream(host string, port int) (*Stream, error) {
	if c == nil || len(c.hops) == 0 {
		return nil, fmt.Errorf("tor: circuit has no hops")
	}
	id := randomStreamID()
	target := fmt.Sprintf("%s:%d\x00", strings.ToLower(host), port)
	exit := len(c.hops) - 1
	if err := c.sendRelayCell(exit, CmdRelay, RelayBegin, id, []byte(target)); err != nil {
		return nil, err
	}
	s := &Stream{
		circuit:       c,
		id:            id,
		packageWindow: StreamWindowInit,
		deliverWindow: StreamWindowInit,
	}
	for {
		hop, cmd, sid, data, err := c.recvRelayCell()
		if err != nil {
			return nil, err
		}
		if hop != exit {
			continue
		}
		if sid != id {
			continue
		}
		switch cmd {
		case RelayConnected:
			return s, nil
		case RelayEnd:
			s.closed = true
			return nil, endReasonError(data)
		case RelayData:
			s.deliverWindow--
			if s.deliverWindow <= StreamWindowThreshold {
				_ = c.sendRelayCell(exit, CmdRelay, RelaySendme, s.id, nil)
				s.deliverWindow += StreamWindowIncrement
			}
			s.pending = append(s.pending, data...)
		}
	}
}

func (s *Stream) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	s.mu.Lock()
	if len(s.pending) > 0 {
		n := copy(p, s.pending)
		s.pending = s.pending[n:]
		s.mu.Unlock()
		return n, nil
	}
	if s.closed {
		s.mu.Unlock()
		return 0, io.EOF
	}
	s.mu.Unlock()

	exit := len(s.circuit.hops) - 1
	for {
		hop, cmd, sid, data, err := s.circuit.recvRelayCell()
		if err != nil {
			return 0, err
		}
		if hop != exit {
			continue
		}
		if sid != s.id {
			continue
		}
		s.mu.Lock()
		switch cmd {
		case RelayData:
			s.deliverWindow--
			if s.deliverWindow <= StreamWindowThreshold {
				_ = s.circuit.sendRelayCell(exit, CmdRelay, RelaySendme, s.id, nil)
				s.deliverWindow += StreamWindowIncrement
			}
			if len(data) == 0 {
				s.mu.Unlock()
				continue
			}
			n := copy(p, data)
			if n < len(data) {
				s.pending = append(s.pending, data[n:]...)
			}
			s.mu.Unlock()
			return n, nil
		case RelayEnd:
			s.closed = true
			s.mu.Unlock()
			return 0, endReasonError(data)
		case RelaySendme:
			s.packageWindow += StreamWindowIncrement
			s.mu.Unlock()
			continue
		case RelayConnected:
			s.mu.Unlock()
			continue
		default:
			s.mu.Unlock()
		}
	}
}

func (s *Stream) Write(p []byte) (int, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return 0, io.ErrClosedPipe
	}
	s.mu.Unlock()

	exit := len(s.circuit.hops) - 1
	total := 0
	for len(p) > 0 {
		s.mu.Lock()
		for s.packageWindow <= 0 && !s.closed {
			s.mu.Unlock()
			hop, cmd, sid, data, err := s.circuit.recvRelayCell()
			if err != nil {
				return total, err
			}
			if hop != exit || sid != s.id {
				continue
			}
			s.mu.Lock()
			switch cmd {
			case RelaySendme:
				s.packageWindow += StreamWindowIncrement
			case RelayData:
				s.deliverWindow--
				if s.deliverWindow <= StreamWindowThreshold {
					_ = s.circuit.sendRelayCell(exit, CmdRelay, RelaySendme, s.id, nil)
					s.deliverWindow += StreamWindowIncrement
				}
				s.pending = append(s.pending, data...)
			case RelayEnd:
				s.closed = true
				s.mu.Unlock()
				return total, endReasonError(data)
			}
		}

		if s.closed {
			s.mu.Unlock()
			return total, io.ErrClosedPipe
		}

		n := len(p)
		if n > MaxRelayData {
			n = MaxRelayData
		}
		dataToSend := p[:n]
		s.packageWindow--
		s.mu.Unlock()

		if err := s.circuit.sendRelayCell(exit, CmdRelay, RelayData, s.id, dataToSend); err != nil {
			return total, err
		}
		total += n
		p = p[n:]
	}
	return total, nil
}

func (s *Stream) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s == nil || s.closed {
		return nil
	}
	s.closed = true
	exit := len(s.circuit.hops) - 1
	_ = s.circuit.sendRelayCell(exit, CmdRelay, RelayEnd, s.id, []byte{6})
	return nil
}

func (s *Stream) LocalAddr() net.Addr  { return streamAddr("tor-local") }
func (s *Stream) RemoteAddr() net.Addr { return streamAddr("tor-remote") }

func (s *Stream) SetDeadline(time.Time) error      { return nil }
func (s *Stream) SetReadDeadline(time.Time) error  { return nil }
func (s *Stream) SetWriteDeadline(time.Time) error { return nil }

type streamAddr string

func (a streamAddr) Network() string { return "tor" }
func (a streamAddr) String() string  { return string(a) }

func randomStreamID() uint16 {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	id := binary.BigEndian.Uint16(b[:])
	if id == 0 {
		id = 1
	}
	return id
}

func endReasonError(data []byte) error {
	if len(data) == 0 {
		return io.EOF
	}
	reasons := map[byte]string{
		1: "misc", 2: "resolve failed", 3: "connection refused", 4: "exit policy",
		5: "circuit destroyed", 6: "done", 7: "timeout", 8: "no route",
		9: "hibernating", 10: "internal", 11: "resource limit", 12: "connection reset",
		13: "tor protocol", 14: "not a directory",
	}
	r := data[0]
	if msg, ok := reasons[r]; ok {
		return fmt.Errorf("tor: stream closed: %s", msg)
	}
	return fmt.Errorf("tor: stream closed: reason %d", r)
}
