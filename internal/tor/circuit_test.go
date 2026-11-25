package tor

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestParseCreated2(t *testing.T) {
	// Valid CREATED2 body: HLEN (2 bytes) = 64, followed by 64 bytes of HDATA
	body := make([]byte, 2+64)
	binary.BigEndian.PutUint16(body[0:2], 64)
	for i := 0; i < 64; i++ {
		body[2+i] = byte(i)
	}

	hlen, hdata, err := parseCreated2(body)
	if err != nil {
		t.Fatalf("parseCreated2 error: %v", err)
	}
	if hlen != 64 {
		t.Errorf("hlen: expected 64, got %d", hlen)
	}
	if len(hdata) != 64 {
		t.Errorf("hdata len: expected 64, got %d", len(hdata))
	}
	if hdata[10] != 10 {
		t.Errorf("hdata content mismatch")
	}

	// Short body
	if _, _, err := parseCreated2([]byte{0}); err == nil {
		t.Error("expected error for short body")
	}

	// Invalid length field
	badLen := make([]byte, 10)
	binary.BigEndian.PutUint16(badLen[0:2], 50)
	if _, _, err := parseCreated2(badLen); err == nil {
		t.Error("expected error for truncated hdata")
	}
}

func TestMakeRelayBody(t *testing.T) {
	cmd := byte(RelayData)
	streamID := uint16(42)
	data := []byte("hello world")

	body, err := makeRelayBody(cmd, streamID, data)
	if err != nil {
		t.Fatalf("makeRelayBody error: %v", err)
	}
	if len(body) != CellBodyLen {
		t.Errorf("body length: expected %d, got %d", CellBodyLen, len(body))
	}
	if body[0] != cmd {
		t.Errorf("command: expected %d, got %d", cmd, body[0])
	}
	sid := binary.BigEndian.Uint16(body[3:5])
	if sid != streamID {
		t.Errorf("streamID: expected %d, got %d", streamID, sid)
	}
	dataLen := int(binary.BigEndian.Uint16(body[9:11]))
	if dataLen != len(data) {
		t.Errorf("data length: expected %d, got %d", len(data), dataLen)
	}
	if !bytes.Equal(body[11:11+len(data)], data) {
		t.Errorf("data content mismatch")
	}

	// Test too long
	huge := make([]byte, MaxRelayData+1)
	if _, err := makeRelayBody(cmd, streamID, huge); err == nil {
		t.Error("expected error for data > MaxRelayData")
	}
}

func TestEndReasonError(t *testing.T) {
	tests := []struct {
		reason byte
		want   string
	}{
		{2, "resolve failed"},
		{3, "connection refused"},
		{4, "exit policy"},
		{6, "done"},
		{12, "connection reset"},
	}
	for _, tc := range tests {
		err := endReasonError([]byte{tc.reason})
		if err == nil || !bytes.Contains([]byte(err.Error()), []byte(tc.want)) {
			t.Errorf("endReasonError(%d): expected %s, got %v", tc.reason, tc.want, err)
		}
	}
}
