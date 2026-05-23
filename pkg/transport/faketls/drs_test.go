package faketls

import "testing"

func TestDRSState_Disabled_BehavesLikeOldCode(t *testing.T) {
	d := NewDRSState(false, false, MaxRecordPayload)
	if got := d.NextChunk(50000); got != MaxRecordPayload {
		t.Errorf("disabled: NextChunk(50000) = %d, want %d", got, MaxRecordPayload)
	}
	d.Advance(MaxRecordPayload)
	if got := d.NextChunk(100); got != 100 {
		t.Errorf("disabled small remainder: got %d, want 100", got)
	}
}

func TestDRSState_SplitOnly(t *testing.T) {
	d := NewDRSState(false, true, MaxRecordPayload)
	if got := d.NextChunk(50000); got != 1 {
		t.Errorf("split first: got %d, want 1", got)
	}
	d.Advance(1)
	if got := d.NextChunk(50000); got != MaxRecordPayload {
		t.Errorf("after split, DRS off: got %d, want %d", got, MaxRecordPayload)
	}
}

func TestDRSState_DRSOnly_RampByRecords(t *testing.T) {
	d := NewDRSState(true, false, MaxRecordPayload)
	for i := range DRSRampRecords {
		if got := d.NextChunk(50000); got != DRSProbeSize {
			t.Errorf("probe record %d: got %d, want %d", i, got, DRSProbeSize)
		}
		d.Advance(DRSProbeSize)
	}
	if got := d.NextChunk(50000); got != MaxRecordPayload {
		t.Errorf("post-ramp by records: got %d, want %d", got, MaxRecordPayload)
	}
}

func TestDRSState_DRSOnly_RampByBytes(t *testing.T) {
	d := NewDRSState(true, false, MaxRecordPayload)
	// One big record (less than the record-count threshold but exceeds byte threshold).
	d.Advance(DRSRampBytes)
	if got := d.NextChunk(50000); got != MaxRecordPayload {
		t.Errorf("post-ramp by bytes: got %d, want %d", got, MaxRecordPayload)
	}
}

func TestDRSState_SplitAndDRSCombined(t *testing.T) {
	d := NewDRSState(true, true, MaxRecordPayload)

	// First call: split-TLS wins — return 1.
	if got := d.NextChunk(50000); got != 1 {
		t.Errorf("first chunk should be 1 byte (split), got %d", got)
	}
	d.Advance(1)

	// Next call: still in probe phase (records=1, bytes=1).
	if got := d.NextChunk(50000); got != DRSProbeSize {
		t.Errorf("second chunk should be probe size, got %d", got)
	}
}

func TestDRSState_PlanSize_NoDRSNoSplit(t *testing.T) {
	d := NewDRSState(false, false, MaxRecordPayload)
	const payload = 50000
	got := d.PlanSize(payload)

	// Same logic as the existing dc_events code path:
	numRecords := (payload + MaxRecordPayload - 1) / MaxRecordPayload
	want := payload + numRecords*RecordHeaderSize
	if got != want {
		t.Errorf("PlanSize disabled: got %d, want %d", got, want)
	}

	// PlanSize must not mutate the state.
	if d.records != 0 || d.bytes != 0 {
		t.Errorf("PlanSize mutated state: records=%d bytes=%d", d.records, d.bytes)
	}
}

func TestDRSState_PlanSize_WithSplitAndDRS(t *testing.T) {
	d := NewDRSState(true, true, MaxRecordPayload)
	const payload = 50000
	got := d.PlanSize(payload)

	// Expected: 1-byte split record, then 7 more probe records of 1369 bytes
	// (reaching DRSRampRecords=8 total), then full-size records for the rest.
	// Total probe-phase payload: 1 + 7*1369 = 9584 bytes.
	// Remaining: 50000 - 9584 = 40416 bytes in full-size records of 16640.
	// Full-size records: ceil(40416/16640) = 3 records.
	// Total records: 1 (split) + 7 (probe) + 3 (full) = 11.
	want := payload + 11*RecordHeaderSize
	if got != want {
		t.Errorf("PlanSize split+DRS: got %d, want %d", got, want)
	}

	// Verify by running the real loop and accumulating.
	remaining := payload
	total := 0
	count := 0
	for remaining > 0 {
		c := d.NextChunk(remaining)
		total += RecordHeaderSize + c
		d.Advance(c)
		remaining -= c
		count++
		if count > 100 {
			t.Fatal("infinite loop guard tripped")
		}
	}
	if total != got {
		t.Errorf("PlanSize predicted %d but real loop produced %d", got, total)
	}
}

func TestDRSState_NextChunk_EmptyRemaining(t *testing.T) {
	d := NewDRSState(true, true, MaxRecordPayload)
	if got := d.NextChunk(0); got != 0 {
		t.Errorf("NextChunk(0) should return 0, got %d", got)
	}
	// Empty calls must not consume the split arming.
	if !d.splitNext {
		t.Error("NextChunk(0) consumed split arming")
	}
}

func TestDRSState_PayloadSmallerThanProbe(t *testing.T) {
	d := NewDRSState(true, false, MaxRecordPayload)
	if got := d.NextChunk(100); got != 100 {
		t.Errorf("probe phase, tiny payload: got %d, want 100", got)
	}
}

func TestDRSState_NoSplit_RemainderOneByte(t *testing.T) {
	d := NewDRSState(false, true, MaxRecordPayload)
	if got := d.NextChunk(1); got != 1 {
		t.Errorf("split with 1-byte payload: got %d, want 1", got)
	}
	d.Advance(1)
	// Subsequent call should not split (consumed).
	if got := d.NextChunk(5); got != 5 {
		t.Errorf("after split with no DRS: got %d, want 5", got)
	}
}
