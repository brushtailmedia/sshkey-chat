package store

// Phase 16 Gap 1 — tests for the pending_device_revocations queue
// helpers. Same shape as the other Phase 16 Gap 1 queue tests.

import (
	"testing"
)

func TestConsumePendingDeviceRevocations_Empty(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	got, err := st.ConsumePendingDeviceRevocations()
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected 0 rows, got %d", len(got))
	}
}

func TestRecordAndConsumePendingDeviceRevocation(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	if err := st.RecordPendingDeviceRevocation("usr_alice", "dev_laptop", "stolen", "os:1000"); err != nil {
		t.Fatalf("record: %v", err)
	}

	got, _ := st.ConsumePendingDeviceRevocations()
	if len(got) != 1 {
		t.Fatalf("expected 1 row, got %d", len(got))
	}
	row := got[0]
	if row.UserID != "usr_alice" {
		t.Errorf("UserID = %q", row.UserID)
	}
	if row.DeviceID != "dev_laptop" {
		t.Errorf("DeviceID = %q", row.DeviceID)
	}
	if row.Reason != "stolen" {
		t.Errorf("Reason = %q", row.Reason)
	}
	if row.RevokedBy != "os:1000" {
		t.Errorf("RevokedBy = %q", row.RevokedBy)
	}
	if row.QueuedAt == 0 {
		t.Error("QueuedAt should be populated")
	}
}

func TestRecordPendingDeviceRevocation_DefaultsReason(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	// Empty reason should default to "admin_action".
	if err := st.RecordPendingDeviceRevocation("usr_alice", "dev_x", "", "os:1000"); err != nil {
		t.Fatalf("record: %v", err)
	}
	got, _ := st.ConsumePendingDeviceRevocations()
	if len(got) != 1 {
		t.Fatalf("expected 1 row, got %d", len(got))
	}
	if got[0].Reason != "admin_action" {
		t.Errorf("Reason = %q, want admin_action", got[0].Reason)
	}
}

func TestConsumePendingDeviceRevocations_AtomicDelete(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	st.RecordPendingDeviceRevocation("usr_alice", "dev_a", "x", "os:1000")
	st.RecordPendingDeviceRevocation("usr_alice", "dev_b", "y", "os:1000")

	first, _ := st.ConsumePendingDeviceRevocations()
	if len(first) != 2 {
		t.Fatalf("first consume: expected 2 rows, got %d", len(first))
	}

	second, _ := st.ConsumePendingDeviceRevocations()
	if len(second) != 0 {
		t.Errorf("second consume should be empty, got %d rows", len(second))
	}
}

func TestRecordPendingDeviceRevocation_PreservesOrder(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	devices := []string{"dev_alpha", "dev_beta", "dev_gamma"}
	for _, d := range devices {
		st.RecordPendingDeviceRevocation("usr_alice", d, "test", "os:1000")
	}

	got, _ := st.ConsumePendingDeviceRevocations()
	if len(got) != len(devices) {
		t.Fatalf("expected %d rows, got %d", len(devices), len(got))
	}
	for i, row := range got {
		if row.DeviceID != devices[i] {
			t.Errorf("row %d DeviceID = %q, want %q", i, row.DeviceID, devices[i])
		}
	}
}
