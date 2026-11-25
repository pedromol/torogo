package torogo

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
)

// SOCKS5Server runs a local SOCKS5 proxy server listening on addr (e.g. "127.0.0.1:9050")
// routing all incoming client connections and DNS requests through Tor.
type SOCKS5Server struct {
	client   *Client
	listener net.Listener
	mu       sync.Mutex
	closed   bool
}

// ListenSOCKS5 starts a local SOCKS5 proxy server on listenAddr (e.g. "127.0.0.1:9050").
// Any application on the system (cURL, Firefox, Telegram, Git, Python) can use this proxy
// as a drop-in replacement for the official C tor daemon.
func (c *Client) ListenSOCKS5(listenAddr string) (*SOCKS5Server, error) {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, fmt.Errorf("torogo: listen socks5 on %s: %w", listenAddr, err)
	}
	s := &SOCKS5Server{
		client:   c,
		listener: ln,
	}
	go s.serve()
	return s, nil
}

// Addr returns the listener's network address.
func (s *SOCKS5Server) Addr() net.Addr {
	return s.listener.Addr()
}

// Close stops the SOCKS5 server.
func (s *SOCKS5Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return s.listener.Close()
}

func (s *SOCKS5Server) serve() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		go s.handleConn(conn)
	}
}

func (s *SOCKS5Server) handleConn(clientConn net.Conn) {
	defer clientConn.Close()

	// 1. SOCKS5 greeting: VER, NMETHODS, METHODS
	var hdr [2]byte
	if _, err := io.ReadFull(clientConn, hdr[:]); err != nil {
		return
	}
	if hdr[0] != 0x05 {
		return
	}
	methods := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(clientConn, methods); err != nil {
		return
	}

	// Reply: VER 5, METHOD 0 (No Auth)
	if _, err := clientConn.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	// 2. Request: VER 5, CMD, RSV 0, ATYP, DST.ADDR, DST.PORT
	var reqHdr [4]byte
	if _, err := io.ReadFull(clientConn, reqHdr[:]); err != nil {
		return
	}
	if reqHdr[0] != 0x05 || reqHdr[1] != 0x01 { // CMD 0x01 = CONNECT
		_, _ = clientConn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	var targetHost string
	switch reqHdr[3] {
	case 0x01: // IPv4
		var ip [4]byte
		if _, err := io.ReadFull(clientConn, ip[:]); err != nil {
			return
		}
		targetHost = net.IP(ip[:]).String()
	case 0x03: // Domain name (remote DNS resolution over Tor - zero local leak!)
		var lenBuf [1]byte
		if _, err := io.ReadFull(clientConn, lenBuf[:]); err != nil {
			return
		}
		domain := make([]byte, int(lenBuf[0]))
		if _, err := io.ReadFull(clientConn, domain); err != nil {
			return
		}
		targetHost = string(domain)
	case 0x04: // IPv6
		var ip [16]byte
		if _, err := io.ReadFull(clientConn, ip[:]); err != nil {
			return
		}
		targetHost = net.IP(ip[:]).String()
	default:
		_, _ = clientConn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	var portBuf [2]byte
	if _, err := io.ReadFull(clientConn, portBuf[:]); err != nil {
		return
	}
	port := int(portBuf[0])<<8 | int(portBuf[1])
	targetAddr := net.JoinHostPort(targetHost, strconv.Itoa(port))

	// Dial through Tor
	torConn, err := s.client.DialContext(context.Background(), "tcp", targetAddr)
	if err != nil {
		_, _ = clientConn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer torConn.Close()

	// Success reply: VER 5, REP 0, RSV 0, ATYP 1, BND.ADDR 127.0.0.1:0
	if _, err := clientConn.Write([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0}); err != nil {
		return
	}

	// Bi-directional pipe
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(torConn, clientConn)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(clientConn, torConn)
		done <- struct{}{}
	}()
	<-done
}
