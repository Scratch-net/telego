package main

import (
	"bytes"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/scratch-net/telego/pkg/transport/middleend"
)

func TestMiddleEndTransportDiagnosticsFollowupUsesPhysicalCorrelation(t *testing.T) {
	now := time.Date(2026, time.September, 12, 12, 0, 0, 0, time.UTC)
	record := middleend.GenerationDiagnosticRecord{
		Kind: middleend.GenerationDiagnosticSlotSocket, At: now, GenerationID: 7,
		Role: middleend.GenerationRoleRetiring, DCID: -2, Slot: 3, Incarnation: 4,
		FailureObservedAt: now.Add(-time.Second),
		Transport: middleend.LinkTransportSnapshot{
			IO: middleend.LinkIOSnapshot{Available: true, ReadBytes: 17, WriteAttemptBytes: 23, LastReadAt: now.Add(-time.Minute),
				WriteInFlight: true, OutboundObserved: true, OutboundProgressIncomplete: true, OutboundProgressBytes: 11},
			Socket: middleend.LinkSocketSnapshot{Status: middleend.LinkSocketAvailable, At: now, State: 8, RTTMicroseconds: 43},
		},
	}
	var output bytes.Buffer
	logger := zerolog.New(&output).Level(zerolog.InfoLevel)
	emitMiddleEndDiagnostic(&logger, record)
	decoded := readDiagnosticJSON(t, output.String())[0]
	if decoded["message"] != middleEndSlotSocketMessage || decoded["diagnostic_kind"] != "slot_socket" ||
		decoded["failure_observed_at"] != record.FailureObservedAt.Format(time.RFC3339Nano) || decoded["incarnation"] != float64(4) ||
		decoded["tcp_info_status"] != "available" || decoded["tcp_state"] != float64(8) || decoded["tcp_rtt_us"] != float64(43) ||
		decoded["wire_read_bytes"] != float64(17) || decoded["wire_write_attempt_bytes"] != float64(23) ||
		decoded["wire_write_in_flight"] != true || decoded["gnet_outbound_progress_incomplete"] != true || decoded["gnet_outbound_progress_bytes"] != float64(11) {
		t.Fatalf("socket evidence = %v", decoded)
	}
	for _, field := range []string{"failure_sequence", "affected_bindings", "reason", "error", "last_wire_write_attempt_at"} {
		if _, exists := decoded[field]; exists {
			t.Errorf("socket record included unrelated or unobserved field %s", field)
		}
	}
}

func TestMiddleEndTransportDiagnosticsAvailability(t *testing.T) {
	for _, status := range []middleend.LinkSocketStatus{"", middleend.LinkSocketNotCaptured, middleend.LinkSocketUnavailable, middleend.LinkSocketUnsupported, middleend.LinkSocketError} {
		t.Run(string(status), func(t *testing.T) {
			var output bytes.Buffer
			logger := zerolog.New(&output)
			event := logger.Info()
			emitMiddleEndTransport(event, middleend.LinkTransportSnapshot{Socket: middleend.LinkSocketSnapshot{Status: status, Errno: 9}})
			event.Msg("availability")
			decoded := readDiagnosticJSON(t, output.String())[0]
			wantStatus := status
			if wantStatus == "" {
				wantStatus = middleend.LinkSocketNotCaptured
			}
			if decoded["tcp_info_status"] != string(wantStatus) || decoded["transport_io_available"] != false {
				t.Fatalf("availability = %v", decoded)
			}
			for _, field := range []string{"tcp_state", "tcp_rtt_us", "tcp_unacked", "wire_read_bytes", "wire_write_attempt_bytes"} {
				if _, exists := decoded[field]; exists {
					t.Errorf("unavailable evidence published numeric %s", field)
				}
			}
		})
	}
}
