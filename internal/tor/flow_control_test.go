package tor

import (
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
