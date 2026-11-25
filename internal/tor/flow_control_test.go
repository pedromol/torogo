package tor

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/binary"
	"net"
	"testing"
)

func TestFlowControlConstants(t *testing.T) {
	if CircWindowInit != 1000 {
		t.Fatalf("expected CircWindowInit 1000, got %d", CircWindowInit)
	}
	if CircWindowIncrement != 100 {
		t.Fatalf("expected CircWindowIncrement 100, got %d", CircWindowIncrement)
	}
	if CircWindowThreshold != 900 {
		t.Fatalf("expected CircWindowThreshold 900, got %d", CircWindowThreshold)
	}
	if StreamWindowInit != 500 {
		t.Fatalf("expected StreamWindowInit 500, got %d", StreamWindowInit)
	}
	if StreamWindowIncrement != 50 {
		t.Fatalf("expected StreamWindowIncrement 50, got %d", StreamWindowIncrement)
	}
	if StreamWindowThreshold != 450 {
		t.Fatalf("expected StreamWindowThreshold 450, got %d", StreamWindowThreshold)
	}
}

func TestStreamWindowFlow(t *testing.T) {
	s := &Stream{
		id:            42,
		packageWindow: StreamWindowInit,
		deliverWindow: StreamWindowInit,
	}

	// Decrement package window
	s.packageWindow--
	if s.packageWindow != 499 {
		t.Fatalf("expected packageWindow 499, got %d", s.packageWindow)
	}

	// Simulate SENDME cell receipt
	s.packageWindow += StreamWindowIncrement
	if s.packageWindow != 549 {
		t.Fatalf("expected packageWindow 549, got %d", s.packageWindow)
	}

	// Simulate receiving 50 cells -> deliverWindow drops to 450
	for i := 0; i < 50; i++ {
		s.deliverWindow--
	}
	if s.deliverWindow != StreamWindowThreshold {
		t.Fatalf("expected deliverWindow at threshold %d, got %d", StreamWindowThreshold, s.deliverWindow)
	}
	// Replenish
	s.deliverWindow += StreamWindowIncrement
	if s.deliverWindow != StreamWindowInit {
		t.Fatalf("expected deliverWindow replenished to %d, got %d", StreamWindowInit, s.deliverWindow)
	}
}

func TestStreamWrite_WaitSendmeWithOtherStreamCells(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	keys := &HopKeys{
		Df: make([]byte, 20),
		Db: make([]byte, 20),
		Kf: make([]byte, 16),
		Kb: make([]byte, 16),
	}
	hop, err := newHop(&RouterStatus{}, &Microdesc{}, keys)
	if err != nil {
		t.Fatalf("newHop: %v", err)
	}

	link := &Link{conn: c1}
	circ := &Circuit{
		link:          link,
		circID:        1,
		hops:          []*Hop{hop},
		packageWindow: CircWindowInit,
		deliverWindow: CircWindowInit,
	}

	stream := &Stream{
		circuit:       circ,
		id:            42,
		packageWindow: 0, // Exhausted, must wait for SENDME
		deliverWindow: StreamWindowInit,
	}

	// Peer setup to craft valid relay cells
	bwdBlock, err := aes.NewCipher(keys.Kb)
	if err != nil {
		t.Fatalf("aes: %v", err)
	}
	peerEnc := cipher.NewCTR(bwdBlock, make([]byte, aes.BlockSize))
	peerDigest := sha1.New()
	peerDigest.Write(keys.Db)

	sendPeerCell := func(cmd byte, streamID uint16, data []byte) {
		body, err := makeRelayBody(cmd, streamID, data)
		if err != nil {
			t.Fatalf("makeRelayBody: %v", err)
		}
		peerDigest.Write(body)
		sum := peerDigest.Sum(nil)
		copy(body[5:9], sum[:4])
		peerEnc.XORKeyStream(body, body)
		if err := writeCell(c2, 1, CmdRelay, body); err != nil {
			t.Fatalf("writeCell: %v", err)
		}
	}

	go func() {
		// 1. Cell for a different stream (sid = 99)
		sendPeerCell(RelayData, 99, []byte("data for other stream"))
		// 2. Cell for another stream (sid = 100)
		sendPeerCell(RelayData, 100, []byte("more data"))
		// 3. SENDME cell for our stream (sid = 42)
		sendPeerCell(RelaySendme, 42, nil)

		// Read outgoing data sent by stream.Write
		_, _ = readCell(c2)
	}()

	n, err := stream.Write([]byte("hello tor"))
	if err != nil {
		t.Fatalf("stream.Write failed: %v", err)
	}
	if n != 9 {
		t.Fatalf("expected 9 bytes written, got %d", n)
	}
}

func TestCircuitDeliverWindow_AuthenticatedSendme(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	keys := &HopKeys{
		Df: make([]byte, 20),
		Db: make([]byte, 20),
		Kf: make([]byte, 16),
		Kb: make([]byte, 16),
	}
	hop, err := newHop(&RouterStatus{}, &Microdesc{}, keys)
	if err != nil {
		t.Fatalf("newHop: %v", err)
	}

	link := &Link{conn: c1}
	circ := &Circuit{
		link:          link,
		circID:        1,
		hops:          []*Hop{hop},
		packageWindow: CircWindowInit,
		deliverWindow: CircWindowThreshold + 1, // 1 cell away from triggering SENDME
	}

	bwdBlock, err := aes.NewCipher(keys.Kb)
	if err != nil {
		t.Fatalf("aes: %v", err)
	}
	peerEnc := cipher.NewCTR(bwdBlock, make([]byte, aes.BlockSize))
	peerDigest := sha1.New()
	peerDigest.Write(keys.Db)

	// Send a RelayData cell from peer
	body, err := makeRelayBody(RelayData, 1, []byte("data payload"))
	if err != nil {
		t.Fatalf("makeRelayBody: %v", err)
	}
	peerDigest.Write(body)
	expectedSum := peerDigest.Sum(nil)
	copy(body[5:9], expectedSum[:4])
	peerEnc.XORKeyStream(body, body)

	go func() {
		_ = writeCell(c2, 1, CmdRelay, body)
	}()

	// Circuit receives relay cell; deliverWindow drops to CircWindowThreshold
	var sendmeCell *Cell
	done := make(chan struct{})
	go func() {
		defer close(done)
		sendmeCell, _ = readCell(c2)
	}()

	hopIdx, cmd, sid, _, err := circ.recvRelayCell()
	if err != nil {
		t.Fatalf("recvRelayCell: %v", err)
	}
	if hopIdx != 0 || cmd != RelayData || sid != 1 {
		t.Fatalf("unexpected recvRelayCell result: hop=%d, cmd=%d, sid=%d", hopIdx, cmd, sid)
	}

	<-done
	if sendmeCell == nil {
		t.Fatal("expected circuit SENDME cell sent to peer")
	}
	if sendmeCell.CircID != 1 || sendmeCell.Command != CmdRelay {
		t.Fatalf("unexpected cell circID=%d, command=%d", sendmeCell.CircID, sendmeCell.Command)
	}

	// Decrypt outgoing SENDME cell
	fwdBlock, err := aes.NewCipher(keys.Kf)
	if err != nil {
		t.Fatalf("aes: %v", err)
	}
	peerDec := cipher.NewCTR(fwdBlock, make([]byte, aes.BlockSize))
	sendmeBody := sendmeCell.Body
	peerDec.XORKeyStream(sendmeBody, sendmeBody)

	if sendmeBody[0] != RelaySendme {
		t.Fatalf("expected RelaySendme, got %d", sendmeBody[0])
	}
	sendmeStreamID := binary.BigEndian.Uint16(sendmeBody[3:5])
	if sendmeStreamID != 0 {
		t.Fatalf("expected circuit SENDME streamID 0, got %d", sendmeStreamID)
	}
	dataLen := int(binary.BigEndian.Uint16(sendmeBody[9:11]))
	if dataLen != 23 {
		t.Fatalf("expected authenticated SENDME payload length 23, got %d", dataLen)
	}
	payload := sendmeBody[11 : 11+dataLen]
	if payload[0] != 0x01 {
		t.Fatalf("expected SENDME version 0x01, got 0x%02x", payload[0])
	}
	digestLen := binary.BigEndian.Uint16(payload[1:3])
	if digestLen != 20 {
		t.Fatalf("expected digest length 20, got %d", digestLen)
	}
	if !bytes.Equal(payload[3:23], expectedSum) {
		t.Fatalf("authenticated SENDME digest mismatch: got %x, want %x", payload[3:23], expectedSum)
	}
}
