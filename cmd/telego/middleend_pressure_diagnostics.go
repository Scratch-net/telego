package main

import (
	"time"

	"github.com/rs/zerolog"
	"github.com/scratch-net/telego/pkg/transport/middleend"
)

func emitMiddleEndResponsePressure(event *zerolog.Event, record middleend.GenerationDiagnosticRecord) {
	p := record.Pressure
	event.Uint64("eviction_sequence", p.EvictionSequence).
		Str("eviction_observed_at", p.ObservedAt.UTC().Format(time.RFC3339Nano)).
		Int("dc", int(record.DCID)).Int("slot", record.Slot).Uint64("incarnation", record.Incarnation).
		Str("pressure_limit", p.Limit.String())
	if record.Kind == middleend.GenerationDiagnosticResponsePressureOutput {
		o := record.PressureOutput
		event.Bool("client_closing", o.Closing).Bool("client_web", o.Web).
			Bool("client_buffered_available", o.BufferedAvailable).
			Int64("client_output_accounted_bytes", o.AccountedBytes).Int("client_output_limit_bytes", o.BufferLimit).
			Int64("shared_output_accounted_bytes", o.SharedAccountedBytes).Int64("shared_output_limit_bytes", o.SharedLimit).
			Str("client_last_response_write_at", o.LastWriteAt.UTC().Format(time.RFC3339Nano)).
			Str("client_last_buffer_decrease_at", o.LastBufferDecreaseAt.UTC().Format(time.RFC3339Nano)).
			Uint64("client_response_write_bytes", o.WriteBytes).Uint64("client_response_write_events", o.WriteEvents).
			Str("client_output_wait", o.Wait.String()).Str("client_output_wait_since", o.WaitSince.UTC().Format(time.RFC3339Nano)).
			Bool("client_output_retry_pending", o.RetryPending).
			Str("client_output_stall_deadline", o.StallDeadline.UTC().Format(time.RFC3339Nano))
		if o.BufferedAvailable {
			event.Int("client_output_buffered_bytes", o.BufferedBytes)
		}
		event.Msg("Middle-End response-pressure client output evidence")
		return
	}
	event.Int("incoming_event_bytes", p.IncomingBytes).
		Int("incoming_dc", int(p.IncomingDCID)).Int("incoming_slot", p.IncomingSlot).
		Uint64("incoming_incarnation", p.IncomingIncarnation).
		Bool("victim_is_incoming", p.VictimIsIncoming).
		Str("victim_queue_nonempty_since", p.QueueNonemptySince.UTC().Format(time.RFC3339Nano)).
		Str("victim_last_dequeue_at", p.LastDequeueAt.UTC().Format(time.RFC3339Nano)).
		Uint64("victim_dequeued_items", p.DequeuedItems).Uint64("victim_dequeued_bytes", p.DequeuedBytes).
		Bool("victim_ready_queued", p.ReadyQueued).Bool("victim_ready_leased", p.ReadyLeased)
	for _, queue := range []struct {
		name  string
		value middleend.ResponseQueueDiagnostic
	}{
		{"incoming", p.Incoming}, {"victim", p.Victim}, {"slot", p.Slot}, {"manager", p.Manager},
	} {
		event.Int(queue.name+"_response_items", queue.value.Items).Int(queue.name+"_response_bytes", queue.value.Bytes).
			Int(queue.name+"_response_limit_items", queue.value.ItemLimit).Int(queue.name+"_response_limit_bytes", queue.value.ByteLimit)
	}
	event.Msg("Middle-End response pressure evicted a client binding")
}
