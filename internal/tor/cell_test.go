package tor

import (
	"bytes"
	"testing"
)

func TestVersionsCellReadWrite(t *testing.T) {
	versions := []uint16{3, 4, 5}
	var buf bytes.Buffer
	if err := writeVersionsCell(&buf, versions); err != nil {
		t.Fatalf("writeVersionsCell error: %v", err)
	}

	readVers, err := readVersionsCell(&buf)
	if err != nil {
		t.Fatalf("readVersionsCell error: %v", err)
	}
	if len(readVers) != len(versions) {
		t.Fatalf("expected %d versions, got %d", len(versions), len(readVers))
	}
	for i := range versions {
		if readVers[i] != versions[i] {
			t.Errorf("version[%d]: expected %d, got %d", i, versions[i], readVers[i])
		}
	}

	// Test invalid versions: wrong command
	badBuf := bytes.NewReader([]byte{0, 0, 99, 0, 2, 0, 4})
	if _, err := readVersionsCell(badBuf); err == nil {
		t.Error("expected error for wrong command in versions cell")
	}

	// Test invalid versions: odd length
	oddBuf := bytes.NewReader([]byte{0, 0, CmdVersions, 0, 3, 0, 4, 0})
	if _, err := readVersionsCell(oddBuf); err == nil {
		t.Error("expected error for odd versions length")
	}
}

func TestFixedCellReadWrite(t *testing.T) {
	var buf bytes.Buffer
	circID := uint32(0x80000001)
	cmd := byte(CmdRelay)
	body := make([]byte, CellBodyLen)
	body[0] = RelayData
	body[1] = 0x42

	if err := writeCell(&buf, circID, cmd, body); err != nil {
		t.Fatalf("writeCell error: %v", err)
	}

	cell, err := readCell(&buf)
	if err != nil {
		t.Fatalf("readCell error: %v", err)
	}
	if cell.CircID != circID {
		t.Errorf("circID: expected 0x%x, got 0x%x", circID, cell.CircID)
	}
	if cell.Command != cmd {
		t.Errorf("cmd: expected %d, got %d", cmd, cell.Command)
	}
	if len(cell.Body) != CellBodyLen {
		t.Errorf("body len: expected %d, got %d", CellBodyLen, len(cell.Body))
	}
	if cell.Body[0] != RelayData || cell.Body[1] != 0x42 {
		t.Errorf("body content mismatch")
	}

	// Test error for oversized fixed cell body
	tooBig := make([]byte, CellBodyLen+1)
	if err := writeCell(&buf, circID, cmd, tooBig); err == nil {
		t.Error("expected error for oversized fixed cell body")
	}
}

func TestPaddingCellFraming(t *testing.T) {
	var buf bytes.Buffer
	padBody := make([]byte, CellBodyLen)
	padBody[0] = 0xAA

	if err := writeCell(&buf, 0, CmdPadding, padBody); err != nil {
		t.Fatalf("writeCell error: %v", err)
	}

	cell, err := readCell(&buf)
	if err != nil {
		t.Fatalf("readCell error: %v", err)
	}
	if cell.CircID != 0 {
		t.Errorf("expected circID 0, got %d", cell.CircID)
	}
	if cell.Command != CmdPadding {
		t.Errorf("expected CmdPadding (%d), got %d", CmdPadding, cell.Command)
	}
	if cell.Body[0] != 0xAA {
		t.Errorf("expected padBody[0] 0xAA, got 0x%02x", cell.Body[0])
	}
}

func TestVariableCellReadWrite(t *testing.T) {
	var buf bytes.Buffer
	circID := uint32(0)
	cmd := byte(CmdCerts)
	payload := []byte{0x01, 0x02, 0x03, 0x04, 0x05}

	if err := writeCell(&buf, circID, cmd, payload); err != nil {
		t.Fatalf("writeCell error: %v", err)
	}

	cell, err := readCell(&buf)
	if err != nil {
		t.Fatalf("readCell error: %v", err)
	}
	if cell.CircID != circID {
		t.Errorf("circID mismatch")
	}
	if cell.Command != cmd {
		t.Errorf("command mismatch")
	}
	if !bytes.Equal(cell.Body, payload) {
		t.Errorf("payload mismatch: got %v, want %v", cell.Body, payload)
	}
}

func TestIsVariableCell(t *testing.T) {
	if !isVariableCell(CmdVersions) || !isVariableCell(CmdCerts) || !isVariableCell(CmdAuthChallenge) {
		t.Errorf("expected variable cells to be true")
	}
	if isVariableCell(CmdRelay) || isVariableCell(CmdCreate2) || isVariableCell(CmdCreated2) {
		t.Errorf("expected fixed cells to be false")
	}
}

func TestRelayHeaderConstants(t *testing.T) {
	if RelayHdrLen != 11 {
		t.Errorf("RelayHdrLen expected 11, got %d", RelayHdrLen)
	}
	if MaxRelayData != CellBodyLen-RelayHdrLen {
		t.Errorf("MaxRelayData mismatch: %d != %d", MaxRelayData, CellBodyLen-RelayHdrLen)
	}
}
