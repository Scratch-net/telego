package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/scratch-net/telego/pkg/transport/middleend"
)

func TestResponsePressureDiagnosticsIncludeQueueAndOwnerEvidence(t *testing.T) {
	at := time.Now()
	record := middleend.GenerationDiagnosticRecord{
		Kind: middleend.GenerationDiagnosticResponsePressure, At: at,
		GenerationID: 7, Role: middleend.GenerationRoleActive, DCID: -2, Slot: 3, Incarnation: 5, AffectedBindings: 1,
		Pressure: middleend.ResponsePressureDiagnostic{
			EvictionSequence: 11, ObservedAt: at, Limit: middleend.ResponsePressureBindingBytes, IncomingBytes: 1040,
			Victim:             middleend.ResponseQueueDiagnostic{Items: 3, Bytes: 2048, ItemLimit: 768, ByteLimit: 2097152},
			QueueNonemptySince: at.Add(-time.Second), ReadyLeased: true,
		},
	}
	var output bytes.Buffer
	logger := zerolog.New(&output).Level(zerolog.InfoLevel)
	emitMiddleEndDiagnostic(&logger, record)
	record.Kind = middleend.GenerationDiagnosticResponsePressureOutput
	record.At = at.Add(time.Millisecond)
	record.AffectedBindings = 0
	record.PressureOutput = middleend.ResponsePressureOutput{At: record.At, Web: true,
		Wait: middleend.ResponseOutputCarrierBudget, RetryPending: true, AccountedBytes: 99}
	emitMiddleEndDiagnostic(&logger, record)
	rows := readDiagnosticJSON(t, output.String())
	if len(rows) != 2 || rows[0]["level"] != "warn" || rows[1]["level"] != "info" ||
		rows[0]["pressure_limit"] != "binding_bytes" || rows[0]["victim_response_bytes"] != float64(2048) ||
		rows[0]["victim_ready_leased"] != true || rows[1]["client_output_wait"] != "carrier_budget" ||
		rows[1]["client_web"] != true || rows[1]["client_output_accounted_bytes"] != float64(99) ||
		rows[0]["eviction_sequence"] != rows[1]["eviction_sequence"] || rows[0]["eviction_observed_at"] != rows[1]["eviction_observed_at"] {
		t.Fatalf("eviction logs lost evidence: %v", rows)
	}
	if _, exists := rows[1]["client_output_buffered_bytes"]; exists {
		t.Fatal("unavailable live buffer reported as zero")
	}
	for _, forbidden := range []string{"connection_id", "client_id", "endpoint", "failure_sequence", "error_code", "probe_id"} {
		if strings.Contains(output.String(), forbidden) {
			t.Errorf("eviction contains unrelated or sensitive field %s", forbidden)
		}
	}
}

func TestResponsePressureDiagnosticsSharedPoolOmitsObsoleteCaps(t *testing.T) {
	at := time.Now()
	record := middleend.GenerationDiagnosticRecord{
		Kind: middleend.GenerationDiagnosticResponsePressure,
		Pressure: middleend.ResponsePressureDiagnostic{
			Limit: middleend.ResponsePressureSharedBudget, ObservedAt: at, SelectionAt: at,
			SelectionReason: middleend.ResponsePressureStalled, IncomingBytes: 512,
			Budget:                  middleend.ResponseBudgetSnapshot{LimitBytes: 8192, UsedBytes: 8000, OrdinaryLimitBytes: 7000},
			RequiredAdditionalBytes: 800, RequiredReclaimBytes: 600, ReclaimedBytes: 720,
			VictimRetainedBytes: 1000, VictimUnreadBytes: 10, VictimQueuedBytes: 720,
			VictimProgressAvailable: true, VictimProgressAge: 3 * time.Second,
			VictimObservationAvailable: true, VictimObservationAge: time.Millisecond,
			Victim: middleend.ResponseQueueDiagnostic{Items: 2, Bytes: 512, ItemLimit: 768, ByteLimit: 2 << 20},
		},
	}
	var output bytes.Buffer
	logger := zerolog.New(&output).Level(zerolog.InfoLevel)
	emitMiddleEndDiagnostic(&logger, record)
	record.Kind = middleend.GenerationDiagnosticResponsePressureOutput
	record.PressureOutput = middleend.ResponsePressureOutput{
		At: at, SharedResponseBudget: true, ResponseBudget: record.Pressure.Budget,
		Wait:                 middleend.ResponseOutputProcessingReserve,
		SharedAccountedBytes: 99, SharedLimit: 1024,
	}
	emitMiddleEndDiagnostic(&logger, record)
	rows := readDiagnosticJSON(t, output.String())
	if len(rows) != 2 || rows[0]["selection_rule"] != "stalled" ||
		rows[0]["reclaimed_retained_bytes"] != float64(720) || rows[0]["victim_response_bytes"] != float64(512) ||
		rows[0]["response_pool_limit_bytes"] != float64(8192) || rows[0]["required_additional_bytes"] != float64(800) ||
		rows[0]["victim_progress_age_ms"] != float64(3000) || rows[1]["client_output_wait"] != "processing_reserve" ||
		rows[1]["response_pool_used_bytes"] != float64(8000) {
		t.Fatalf("shared telemetry lost distinct evidence: %+v", rows)
	}
	for _, forbidden := range []string{"response_limit_items", "response_limit_bytes", "shared_output_limit_bytes", "shared_output_accounted_bytes", "connection_id", "client_id"} {
		if strings.Contains(output.String(), forbidden) {
			t.Fatalf("shared evidence exported obsolete capacity or identity: %s", forbidden)
		}
	}
}
