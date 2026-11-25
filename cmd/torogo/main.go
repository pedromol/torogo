package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/pedromol/torogo"
)

const targetHost = "check.torproject.org"

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if err := run(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "torogo:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	fmt.Fprintln(os.Stderr, "initializing torogo client...")
	client, err := torogo.NewClient(ctx)
	if err != nil {
		return err
	}
	defer client.Close()

	httpClient := client.HTTPClient()

	fmt.Fprintln(os.Stderr, "making HTTP request over Tor...")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+targetHost+"/api/ip", nil)
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
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("target HTTP status: %s", resp.Status)
	}

	var out struct {
		IsTor bool   `json:"IsTor"`
		IP    string `json:"IP"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return fmt.Errorf("parse target response: %w", err)
	}
	fmt.Printf("circuit established\nIsTor=%v IP=%s\n", out.IsTor, out.IP)
	if !out.IsTor {
		return fmt.Errorf("exit is not recognized as a Tor exit")
	}
	return nil
}
