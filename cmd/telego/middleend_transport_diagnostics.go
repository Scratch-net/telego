package main

import (
	"time"

	"github.com/rs/zerolog"

	"github.com/scratch-net/telego/pkg/transport/middleend"
)

func emitMiddleEndTransport(event *zerolog.Event, snapshot middleend.LinkTransportSnapshot) {
	io := snapshot.IO
	event.Bool("transport_io_available", io.Available)
	if io.Available {
		event.
			Uint64("wire_read_bytes", io.ReadBytes).
			Uint64("wire_read_events", io.ReadEvents).
			Uint64("wire_write_attempt_bytes", io.WriteAttemptBytes).
			Uint64("wire_write_attempts", io.WriteAttempts).
			Bool("wire_write_in_flight", io.WriteInFlight).
			Bool("gnet_outbound_observed", io.OutboundObserved)
		emitMiddleEndObservedTime(event, "last_wire_read_at", io.LastReadAt)
		emitMiddleEndObservedTime(event, "last_wire_write_attempt_at", io.LastWriteAttemptAt)
		if io.OutboundObserved {
			event.
				Int("gnet_outbound_buffered_bytes", io.OutboundBufferedBytes).
				Uint64("gnet_outbound_progress_bytes", io.OutboundProgressBytes).
				Bool("gnet_outbound_progress_incomplete", io.OutboundProgressIncomplete)
			emitMiddleEndObservedTime(event, "gnet_outbound_observed_at", io.OutboundObservedAt)
			emitMiddleEndObservedTime(event, "last_gnet_outbound_progress_at", io.LastOutboundProgressAt)
		}
	}
	socket := snapshot.Socket
	status := socket.Status
	if status == "" {
		status = middleend.LinkSocketNotCaptured
	}
	event.Str("tcp_info_status", string(status))
	emitMiddleEndObservedTime(event, "tcp_info_observed_at", socket.At)
	if status == middleend.LinkSocketError {
		event.Uint64("tcp_info_errno", socket.Errno)
	}
	if status == middleend.LinkSocketAvailable {
		event.
			Uint8("tcp_state", socket.State).
			Uint32("tcp_unacked", socket.Unacked).
			Uint32("tcp_lost", socket.Lost).
			Uint32("tcp_retrans", socket.Retrans).
			Uint32("tcp_total_retrans", socket.TotalRetrans).
			Uint32("tcp_rtt_us", socket.RTTMicroseconds).
			Uint32("tcp_rttvar_us", socket.RTTVarMicroseconds).
			Uint32("tcp_snd_cwnd", socket.SendCongestionWindow)
	}
}

func emitMiddleEndObservedTime(event *zerolog.Event, name string, observed time.Time) {
	if !observed.IsZero() {
		event.Str(name, observed.UTC().Format(time.RFC3339Nano))
	}
}
