package tor

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"time"
)

type Link struct {
	conn    *tls.Conn
	version int
}

type certEntry struct {
	Type byte
	Cert []byte
}

func DialLink(ctx context.Context, ip string, orPort int, edID [32]byte) (*Link, error) {
	d := &net.Dialer{Timeout: 10 * time.Second}
	return DialLinkWithDialer(ctx, d, ip, orPort, edID)
}

func DialLinkWithDialer(ctx context.Context, dialer ContextDialer, ip string, orPort int, edID [32]byte) (*Link, error) {
	if dialer == nil {
		dialer = &net.Dialer{Timeout: 10 * time.Second}
	}
	addr := net.JoinHostPort(ip, strconv.Itoa(orPort))
	raw, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	tlsConn := tls.Client(raw, &tls.Config{
		InsecureSkipVerify: true, // Tor relay certs are self-signed; CERTS binds them.
		MinVersion:         tls.VersionTLS12,
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, fmt.Errorf("tor: TLS handshake with %s: %w", addr, err)
	}
	if err := writeVersionsCell(tlsConn, []uint16{4, 5}); err != nil {
		tlsConn.Close()
		return nil, err
	}
	versions, err := readVersionsCell(tlsConn)
	if err != nil {
		tlsConn.Close()
		return nil, err
	}
	canV4 := false
	for _, v := range versions {
		if v == 4 {
			canV4 = true
		}
	}
	if !canV4 {
		tlsConn.Close()
		return nil, fmt.Errorf("tor: relay %s does not support link protocol 4", addr)
	}

	var certs []certEntry
	for {
		cell, err := readCell(tlsConn)
		if err != nil {
			tlsConn.Close()
			return nil, err
		}
		switch cell.Command {
		case CmdCerts:
			certs, err = parseCertBody(cell.Body)
			if err != nil {
				tlsConn.Close()
				return nil, err
			}
		case CmdAuthChallenge:
			// We do not authenticate as a client.
		case CmdVPadding, CmdPadding:
			// Ignore padding.
		case CmdNetinfo:
			goto handshakeDone
		default:
			tlsConn.Close()
			return nil, fmt.Errorf("tor: unexpected cell %d during link handshake", cell.Command)
		}
	}

handshakeDone:
	if err := validateLinkCerts(certs, edID, tlsConn); err != nil {
		tlsConn.Close()
		return nil, err
	}
	netinfo := make([]byte, CellBodyLen)
	binary.BigEndian.PutUint32(netinfo[0:4], uint32(time.Now().Unix()))
	parsedIP := net.ParseIP(ip)
	if ip4 := parsedIP.To4(); ip4 != nil {
		netinfo[4] = 0x04
		netinfo[5] = 0x04
		copy(netinfo[6:10], ip4)
		netinfo[10] = 0
	} else if ip6 := parsedIP.To16(); ip6 != nil {
		netinfo[4] = 0x06
		netinfo[5] = 16
		copy(netinfo[6:22], ip6)
		netinfo[22] = 0
	}
	if err := writeCell(tlsConn, 0, CmdNetinfo, netinfo); err != nil {
		tlsConn.Close()
		return nil, err
	}
	return &Link{conn: tlsConn, version: 4}, nil
}

func parseCertBody(body []byte) ([]certEntry, error) {
	if len(body) < 1 {
		return nil, fmt.Errorf("tor: empty CERTS body")
	}
	n := int(body[0])
	off := 1
	certs := make([]certEntry, 0, n)
	for i := 0; i < n; i++ {
		if off+3 > len(body) {
			return nil, fmt.Errorf("tor: truncated CERTS")
		}
		t := body[off]
		l := int(binary.BigEndian.Uint16(body[off+1 : off+3]))
		off += 3
		if off+l > len(body) {
			return nil, fmt.Errorf("tor: truncated certificate")
		}
		certs = append(certs, certEntry{Type: t, Cert: append([]byte(nil), body[off:off+l]...)})
		off += l
	}
	return certs, nil
}

func validateLinkCerts(certs []certEntry, edID [32]byte, conn *tls.Conn) error {
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return fmt.Errorf("tor: relay presented no TLS certificate")
	}
	tlsHash := sha256.Sum256(state.PeerCertificates[0].Raw)

	var idCert, signCert *Ed25519Cert
	for _, entry := range certs {
		switch entry.Type {
		case 4:
			c, err := parseEd25519Cert(entry.Cert)
			if err != nil {
				return err
			}
			idCert = c
		case 5:
			c, err := parseEd25519Cert(entry.Cert)
			if err != nil {
				return err
			}
			signCert = c
		}
	}
	if idCert == nil || signCert == nil {
		return fmt.Errorf("tor: relay omitted Ed25519 identity/signing certs")
	}
	now := time.Now().UTC()
	if !idCert.validAt(now) || !signCert.validAt(now) {
		return fmt.Errorf("tor: relay Ed25519 cert expired")
	}
	if idCert.CertType != 4 || idCert.KeyType != 1 {
		return fmt.Errorf("tor: unexpected relay identity cert type")
	}
	if !idCert.Verify(ed25519.PublicKey(edID[:])) {
		return fmt.Errorf("tor: relay Ed25519 identity cert signature invalid")
	}
	signingKey := idCert.Subject
	signedWith := idCert.Extension(4)
	if signedWith != nil && (len(signedWith) != 32 || [32]byte(signedWith) != edID) {
		return fmt.Errorf("tor: relay signing key extension mismatch")
	}
	if signCert.CertType != 5 || signCert.KeyType != 3 {
		return fmt.Errorf("tor: unexpected relay TLS cert type")
	}
	if signCert.Subject != tlsHash {
		return fmt.Errorf("tor: relay TLS certificate digest mismatch")
	}
	if !signCert.Verify(ed25519.PublicKey(signingKey[:])) {
		return fmt.Errorf("tor: relay TLS cert signature invalid")
	}
	return nil
}

func (l *Link) sendCell(circID uint32, cmd byte, body []byte) error {
	return writeCell(l.conn, circID, cmd, body)
}

func (l *Link) recvCell() (*Cell, error) {
	return readCell(l.conn)
}

func (l *Link) Close() error {
	if l == nil || l.conn == nil {
		return nil
	}
	return l.conn.Close()
}

// SendPadding sends a link-level padding cell (CmdPadding with circID 0) to prevent NAT/firewall timeouts.
func (l *Link) SendPadding() error {
	pad := make([]byte, CellBodyLen)
	return l.sendCell(0, CmdPadding, pad)
}
