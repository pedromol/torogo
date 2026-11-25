package torogo

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pedromol/torogo/internal/tor"
)

// Client represents a Tor client instance capable of dialing TCP streams
// and executing HTTP requests over the Tor network.
type Client struct {
	mu        sync.RWMutex
	consensus *tor.Consensus
	guardMgr  *tor.GuardManager
	opts      clientOptions
	closed    bool
}

type clientOptions struct {
	circuitTimeout time.Duration
	skipBootstrap  bool
	guardPath      string
	disableGuards  bool
	bridgeConfig   *tor.BridgeConfig
	bridgeDialer   tor.ContextDialer
}

// Option represents a configuration option for Client.
type Option func(*clientOptions)

// WithCircuitTimeout configures the timeout for individual circuit build operations.
func WithCircuitTimeout(d time.Duration) Option {
	return func(o *clientOptions) {
		o.circuitTimeout = d
	}
}

// WithLazyBootstrap delays downloading directory consensus until the first Dial call.
func WithLazyBootstrap() Option {
	return func(o *clientOptions) {
		o.skipBootstrap = true
	}
}

// WithGuardFile sets a custom file path for storing persistent guards.
func WithGuardFile(filePath string) Option {
	return func(o *clientOptions) {
		o.guardPath = filePath
	}
}

// WithDisableGuards disables persistent guard storage on disk.
func WithDisableGuards() Option {
	return func(o *clientOptions) {
		o.disableGuards = true
	}
}

// WithSocks5Proxy routes all Tor guard/bridge ORPort connections through a local SOCKS5 proxy
// (e.g., from a Pluggable Transport like obfs4proxy or snowflake-client).
func WithSocks5Proxy(proxyAddr string) Option {
	return func(o *clientOptions) {
		o.bridgeDialer = &tor.Socks5Dialer{ProxyAddr: proxyAddr}
	}
}

// WithBridge parses a Tor Bridge line and configures Pluggable Transport routing.
func WithBridge(bridgeLine string, proxyAddr string) Option {
	return func(o *clientOptions) {
		cfg, err := tor.ParseBridgeLine(bridgeLine)
		if err == nil {
			if proxyAddr != "" {
				cfg.ProxyAddr = proxyAddr
				o.bridgeDialer = &tor.Socks5Dialer{ProxyAddr: proxyAddr}
			}
			o.bridgeConfig = cfg
		}
	}
}

// NewClient creates and initializes a Tor client.
// By default, it immediately bootstraps by downloading and validating the directory consensus.
func NewClient(ctx context.Context, opts ...Option) (*Client, error) {
	options := clientOptions{
		circuitTimeout: 45 * time.Second,
	}
	for _, opt := range opts {
		opt(&options)
	}

	c := &Client{
		opts: options,
	}

	if !options.disableGuards {
		gm, err := tor.NewGuardManager(options.guardPath)
		if err == nil {
			c.guardMgr = gm
		}
	}

	if !options.skipBootstrap {
		if _, err := c.getConsensus(ctx); err != nil {
			return nil, fmt.Errorf("torogo: bootstrap failed: %w", err)
		}
	}

	return c, nil
}

// getConsensus returns a valid cached consensus or downloads a new one.
func (c *Client) getConsensus(ctx context.Context) (*tor.Consensus, error) {
	c.mu.RLock()
	if c.closed {
		c.mu.RUnlock()
		return nil, errors.New("torogo: client is closed")
	}
	now := time.Now().UTC()
	if c.consensus != nil && c.consensus.ValidAt(now) {
		cons := c.consensus
		c.mu.RUnlock()
		return cons, nil
	}
	c.mu.RUnlock()

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, errors.New("torogo: client is closed")
	}
	now = time.Now().UTC()
	if c.consensus != nil && c.consensus.ValidAt(now) {
		return c.consensus, nil
	}

	cons, err := tor.FetchConsensus(ctx)
	if err != nil {
		return nil, err
	}
	c.consensus = cons
	return cons, nil
}

// DialContext establishes a TCP stream through a 3-hop Tor circuit to the given address.
func (c *Client) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, fmt.Errorf("torogo: unsupported network %q", network)
	}

	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("torogo: invalid address %q: %w", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return nil, fmt.Errorf("torogo: invalid port %q", portStr)
	}

	if strings.HasSuffix(strings.ToLower(host), ".onion") {
		if _, err := tor.ParseOnionV3(host); err != nil {
			return nil, fmt.Errorf("torogo: invalid .onion destination: %w", err)
		}
	}

	cons, err := c.getConsensus(ctx)
	if err != nil {
		return nil, err
	}

	path, err := tor.SelectPathWithGuards(ctx, cons, port, c.guardMgr)
	if err != nil {
		return nil, fmt.Errorf("torogo: select path: %w", err)
	}

	guard := path.Routers[0]
	var edID [32]byte
	copy(edID[:], path.Microdescs[0].Ed25519ID)

	linkCtx := ctx
	if c.opts.circuitTimeout > 0 {
		var cancel context.CancelFunc
		linkCtx, cancel = context.WithTimeout(ctx, c.opts.circuitTimeout)
		defer cancel()
	}

	link, err := tor.DialLinkWithDialer(linkCtx, c.opts.bridgeDialer, guard.IP.String(), int(guard.ORPort), edID)
	if err != nil {
		return nil, fmt.Errorf("torogo: dial guard: %w", err)
	}

	circ, err := tor.NewCircuit(link, guard, path.Microdescs[0])
	if err != nil {
		link.Close()
		return nil, fmt.Errorf("torogo: create circuit: %w", err)
	}

	if err := circ.Extend(path.Routers[1], path.Microdescs[1]); err != nil {
		circ.Close()
		return nil, fmt.Errorf("torogo: extend to middle: %w", err)
	}

	if err := circ.Extend(path.Routers[2], path.Microdescs[2]); err != nil {
		circ.Close()
		return nil, fmt.Errorf("torogo: extend to exit: %w", err)
	}

	stream, err := circ.OpenStream(host, port)
	if err != nil {
		circ.Close()
		return nil, fmt.Errorf("torogo: open stream: %w", err)
	}

	return &torConn{
		Stream: stream,
		circ:   circ,
	}, nil
}

// Dial establishes a connection using the background context.
func (c *Client) Dial(network, addr string) (net.Conn, error) {
	return c.DialContext(context.Background(), network, addr)
}

// Transport returns an *http.Transport configured to route all traffic through Tor circuits.
func (c *Client) Transport() *http.Transport {
	return &http.Transport{
		DialContext:           c.DialContext,
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   20 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}
}

// HTTPClient returns an *http.Client configured to route all HTTP/HTTPS requests through Tor.
func (c *Client) HTTPClient() *http.Client {
	return &http.Client{
		Transport: c.Transport(),
		Timeout:   2 * time.Minute,
	}
}

// Close closes the client.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	c.consensus = nil
	return nil
}

type torConn struct {
	*tor.Stream
	circ *tor.Circuit
}

func (c *torConn) Close() error {
	var err1, err2 error
	if c.Stream != nil {
		err1 = c.Stream.Close()
	}
	if c.circ != nil {
		err2 = c.circ.Close()
	}
	if err1 != nil {
		return err1
	}
	return err2
}
