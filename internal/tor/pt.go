package tor

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ContextDialer is an interface for establishing network connections with a context.
type ContextDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// BridgeConfig represents a configured Pluggable Transport bridge.
type BridgeConfig struct {
	Transport   string            `json:"transport"`   // e.g. "obfs4", "snowflake", "meek", "socks5"
	Address     string            `json:"address"`     // Bridge IP:port
	Fingerprint string            `json:"fingerprint"` // Optional 40-character hex identity
	Args        map[string]string `json:"args"`        // Additional bridge arguments (cert, iat-mode, etc.)
	ProxyAddr   string            `json:"proxy_addr"`  // SOCKS5 proxy address (e.g. "127.0.0.1:9050")
}

// ParseBridgeLine parses a standard Tor bridge line format:
// "Bridge [transport] IP:Port [Fingerprint] [key=value ...]"
func ParseBridgeLine(line string) (*BridgeConfig, error) {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return nil, errors.New("tor: empty bridge line")
	}

	idx := 0
	if strings.EqualFold(fields[0], "Bridge") {
		idx++
		if len(fields) <= idx {
			return nil, errors.New("tor: invalid bridge line")
		}
	}

	transport := "vanilla"
	// If the next field doesn't contain a colon (IP:Port), it's the transport name
	if !strings.Contains(fields[idx], ":") {
		transport = fields[idx]
		idx++
		if len(fields) <= idx {
			return nil, errors.New("tor: missing bridge address")
		}
	}

	addr := fields[idx]
	idx++

	var fingerprint string
	args := make(map[string]string)

	for idx < len(fields) {
		f := fields[idx]
		if strings.Contains(f, "=") {
			parts := strings.SplitN(f, "=", 2)
			args[parts[0]] = parts[1]
		} else if len(f) == 40 && isHex(f) {
			fingerprint = strings.ToUpper(f)
		}
		idx++
	}

	return &BridgeConfig{
		Transport:   transport,
		Address:     addr,
		Fingerprint: fingerprint,
		Args:        args,
	}, nil
}

func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// Socks5Dialer connects to a target host through a SOCKS5 proxy (RFC 1928) in pure Go.
type Socks5Dialer struct {
	ProxyAddr string
	Timeout   time.Duration
}

// DialContext establishes a connection through the SOCKS5 proxy.
func (d *Socks5Dialer) DialContext(ctx context.Context, network, targetAddr string) (net.Conn, error) {
	timeout := d.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", d.ProxyAddr)
	if err != nil {
		return nil, fmt.Errorf("tor: dial socks5 proxy %s: %w", d.ProxyAddr, err)
	}

	// SOCKS5 Handshake
	// 1. Client greeting: Version 5, 1 authentication method (0x00 No Authentication)
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		conn.Close()
		return nil, fmt.Errorf("tor: socks5 greeting write: %w", err)
	}

	// 2. Server method choice
	var resp [2]byte
	if _, err := io.ReadFull(conn, resp[:]); err != nil {
		conn.Close()
		return nil, fmt.Errorf("tor: socks5 greeting read: %w", err)
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("tor: socks5 auth unsupported: %v", resp)
	}

	// 3. Connect request: VER 5, CMD 1 (CONNECT), RSV 0, ATYP, DST.ADDR, DST.PORT
	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("tor: invalid target address: %w", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		conn.Close()
		return nil, fmt.Errorf("tor: invalid target port: %s", portStr)
	}

	var req []byte
	ip := net.ParseIP(host)
	if ip4 := ip.To4(); ip4 != nil {
		req = append([]byte{0x05, 0x01, 0x00, 0x01}, ip4...)
	} else if ip6 := ip.To16(); ip6 != nil {
		req = append([]byte{0x05, 0x01, 0x00, 0x04}, ip6...)
	} else {
		// Domain name
		if len(host) > 255 {
			conn.Close()
			return nil, fmt.Errorf("tor: target domain too long")
		}
		req = append([]byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}, []byte(host)...)
	}
	req = append(req, byte(port>>8), byte(port))

	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, fmt.Errorf("tor: socks5 connect request write: %w", err)
	}

	// 4. Server connect reply: VER, REP, RSV, ATYP, BND.ADDR, BND.PORT
	var replyHdr [4]byte
	if _, err := io.ReadFull(conn, replyHdr[:]); err != nil {
		conn.Close()
		return nil, fmt.Errorf("tor: socks5 connect response read: %w", err)
	}
	if replyHdr[0] != 0x05 {
		conn.Close()
		return nil, fmt.Errorf("tor: invalid socks5 reply version: %d", replyHdr[0])
	}
	if replyHdr[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("tor: socks5 connect failed with status 0x%02x", replyHdr[1])
	}

	// Discard bound address
	switch replyHdr[3] {
	case 0x01: // IPv4 (4 bytes + 2 port)
		var bnd [6]byte
		_, _ = io.ReadFull(conn, bnd[:])
	case 0x03: // Domain (1 len + N domain + 2 port)
		var l [1]byte
		_, _ = io.ReadFull(conn, l[:])
		bnd := make([]byte, int(l[0])+2)
		_, _ = io.ReadFull(conn, bnd)
	case 0x04: // IPv6 (16 bytes + 2 port)
		var bnd [18]byte
		_, _ = io.ReadFull(conn, bnd[:])
	}

	return conn, nil
}

// ManagedPTClient manages a Pluggable Transport subprocess per Tor PT v2.1 specification.
type ManagedPTClient struct {
	cmd      *exec.Cmd
	stateDir string
	mu       sync.Mutex
	methods  map[string]string // transport -> SOCKS5 proxy addr
}

// LaunchManagedPT starts a Pluggable Transport client binary and awaits CMETHOD announcements.
func LaunchManagedPT(ctx context.Context, binaryPath string, transports []string, stateDir string) (*ManagedPTClient, error) {
	if stateDir == "" {
		tmp, err := os.MkdirTemp("", "torogo-pt-*")
		if err != nil {
			return nil, err
		}
		stateDir = tmp
	}

	cmd := exec.CommandContext(ctx, binaryPath)
	cmd.Env = append(os.Environ(),
		"TOR_PT_MANAGED_TRANSPORT_VER=1",
		fmt.Sprintf("TOR_PT_CLIENT_TRANSPORTS=%s", strings.Join(transports, ",")),
		fmt.Sprintf("TOR_PT_STATE_LOCATION=%s", stateDir),
	)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("tor: failed to start PT process %s: %w", binaryPath, err)
	}

	client := &ManagedPTClient{
		cmd:      cmd,
		stateDir: stateDir,
		methods:  make(map[string]string),
	}

	scanner := bufio.NewScanner(stdout)
	done := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "CMETHODS DONE" {
			done = true
			break
		}
		if strings.HasPrefix(line, "CMETHOD ") {
			parts := strings.Fields(line)
			if len(parts) >= 4 && parts[2] == "socks5" {
				client.methods[parts[1]] = parts[3]
			}
		} else if strings.HasPrefix(line, "CMETHOD-ERROR ") {
			_ = client.Close()
			return nil, fmt.Errorf("tor: PT method error: %s", line)
		} else if strings.HasPrefix(line, "ENV-ERROR ") {
			_ = client.Close()
			return nil, fmt.Errorf("tor: PT env error: %s", line)
		}
	}

	if !done && len(client.methods) == 0 {
		_ = client.Close()
		return nil, fmt.Errorf("tor: PT terminated without CMETHODS DONE")
	}

	return client, nil
}

// ProxyAddr returns the SOCKS5 proxy address for the given transport name.
func (pt *ManagedPTClient) ProxyAddr(transport string) (string, bool) {
	pt.mu.Lock()
	defer pt.mu.Unlock()
	addr, ok := pt.methods[transport]
	return addr, ok
}

// Close stops the PT process and cleans up temporary state.
func (pt *ManagedPTClient) Close() error {
	pt.mu.Lock()
	defer pt.mu.Unlock()
	if pt.cmd != nil && pt.cmd.Process != nil {
		_ = pt.cmd.Process.Kill()
		_ = pt.cmd.Wait()
	}
	if pt.stateDir != "" {
		_ = os.RemoveAll(pt.stateDir)
	}
	return nil
}
