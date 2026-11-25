package tor

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestParseCertBody(t *testing.T) {
	// Construct CERTS cell payload:
	// N (1 byte) = 2
	// Entry 1:
	//   Type (1 byte) = 4
	//   Len (2 bytes) = 5
	//   Cert = []byte{1, 2, 3, 4, 5}
	// Entry 2:
	//   Type (1 byte) = 5
	//   Len (2 bytes) = 3
	//   Cert = []byte{10, 20, 30}

	var body []byte
	body = append(body, 2) // N = 2

	// Entry 1
	body = append(body, 4)
	l1 := make([]byte, 2)
	binary.BigEndian.PutUint16(l1, 5)
	body = append(body, l1...)
	body = append(body, 1, 2, 3, 4, 5)

	// Entry 2
	body = append(body, 5)
	l2 := make([]byte, 2)
	binary.BigEndian.PutUint16(l2, 3)
	body = append(body, l2...)
	body = append(body, 10, 20, 30)

	entries, err := parseCertBody(body)
	if err != nil {
		t.Fatalf("parseCertBody error: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	if entries[0].Type != 4 || !bytes.Equal(entries[0].Cert, []byte{1, 2, 3, 4, 5}) {
		t.Errorf("entry 0 mismatch: %+v", entries[0])
	}
	if entries[1].Type != 5 || !bytes.Equal(entries[1].Cert, []byte{10, 20, 30}) {
		t.Errorf("entry 1 mismatch: %+v", entries[1])
	}

	// Empty body error
	if _, err := parseCertBody(nil); err == nil {
		t.Error("expected error for empty CERTS body")
	}

	// Truncated header error
	if _, err := parseCertBody([]byte{1, 4}); err == nil {
		t.Error("expected error for truncated CERTS entry")
	}

	// Truncated cert data error
	if _, err := parseCertBody([]byte{1, 4, 0, 10, 1, 2}); err == nil {
		t.Error("expected error for truncated cert data")
	}
}
