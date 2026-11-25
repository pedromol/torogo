package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/pedromol/torogo"
)

const defaultCheckHost = "check.torproject.org"

func main() {
	var (
		socksAddr   = flag.String("socks", "", "Start local SOCKS5 proxy listener (e.g. 127.0.0.1:9050)")
		controlAddr = flag.String("control", "", "Start Tor Control Port listener (e.g. 127.0.0.1:9051)")
		resolveHost = flag.String("resolve", "", "Perform remote DNS resolution over Tor without leaking queries")
	)
	flag.Parse()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	client, err := torogo.NewClient(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "torogo: bootstrap error: %v\n", err)
		os.Exit(1)
	}
	defer client.Close()

	if *resolveHost != "" {
		ips, err := client.Resolve(ctx, *resolveHost)
		if err != nil {
			fmt.Fprintf(os.Stderr, "torogo: resolve error: %v\n", err)
			os.Exit(1)
		}
		for _, ip := range ips {
			fmt.Println(ip)
		}
		return
	}

	if *socksAddr != "" || *controlAddr != "" {
		if *socksAddr != "" {
			srv, err := client.ListenSOCKS5(*socksAddr)
			if err != nil {
				fmt.Fprintf(os.Stderr, "torogo: socks5 error: %v\n", err)
				os.Exit(1)
			}
			defer srv.Close()
			fmt.Printf("Torogo SOCKS5 proxy listening on %s\n", srv.Addr())
		}
		if *controlAddr != "" {
			ctrl, err := client.ListenControl(*controlAddr)
			if err != nil {
				fmt.Fprintf(os.Stderr, "torogo: control port error: %v\n", err)
				os.Exit(1)
			}
			defer ctrl.Close()
			fmt.Printf("Torogo Control Port listening on %s\n", ctrl.Addr())
		}

		fmt.Println("Tor daemon is running. Press Ctrl+C to terminate.")
		<-ctx.Done()
		fmt.Println("\nShutting down Torogo...")
		return
	}

	// Default run: HTTP connectivity test over Tor
	if err := checkConnectivity(ctx, client); err != nil {
		fmt.Fprintln(os.Stderr, "torogo:", err)
		os.Exit(1)
	}
}

func checkConnectivity(ctx context.Context, client *torogo.Client) error {
	fmt.Fprintln(os.Stderr, "initializing torogo client...")
	fmt.Fprintln(os.Stderr, "making HTTP request over Tor...")

	httpClient := client.HTTPClient()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+defaultCheckHost+"/api/ip", nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "torogo/0.1")

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	var status struct {
		IsTor bool   `json:"IsTor"`
		IP    string `json:"IP"`
	}
	if err := json.Unmarshal(body, &status); err != nil {
		return fmt.Errorf("bad JSON from check service: %w", err)
	}

	fmt.Println("circuit established")
	fmt.Printf("IsTor=%t IP=%s\n", status.IsTor, status.IP)
	return nil
}
