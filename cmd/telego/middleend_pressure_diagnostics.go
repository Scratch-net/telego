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
			Bool("shared_response_budget", o.SharedResponseBudget).
			Str("client_last_response_write_at", o.LastWriteAt.UTC().Format(time.RFC3339Nano)).
			Str("client_last_buffer_decrease_at", o.LastBufferDecreaseAt.UTC().Format(time.RFC3339Nano)).
			Uint64("client_response_write_bytes", o.WriteBytes).Uint64("client_response_write_events", o.WriteEvents).
			Str("client_output_wait", o.Wait.String()).Str("client_output_wait_since", o.WaitSince.UTC().Format(time.RFC3339Nano)).
			Bool("client_output_retry_pending", o.RetryPending).
			Str("client_output_stall_deadline", o.StallDeadline.UTC().Format(time.RFC3339Nano))
		if o.SharedResponseBudget {
			event.Int("response_pool_used_bytes", o.ResponseBudget.UsedBytes).
				Int("response_pool_limit_bytes", o.ResponseBudget.LimitBytes)
		} else {
			event.Int64("shared_output_accounted_bytes", o.SharedAccountedBytes).Int64("shared_output_limit_bytes", o.SharedLimit)
		}
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
	if p.Limit == middleend.ResponsePressureSharedBudget {
		event.Str("selection_rule", p.SelectionReason.String()).
			Str("selection_observed_at", p.SelectionAt.UTC().Format(time.RFC3339Nano)).
			Int("response_pool_used_bytes", p.Budget.UsedBytes).Int("response_pool_limit_bytes", p.Budget.LimitBytes).
			Int("response_ordinary_used_bytes", p.Budget.ClassBytes[middleend.ResponseMemoryOrdinary]).Int("response_ordinary_limit_bytes", p.Budget.OrdinaryLimitBytes).
			Int("required_additional_bytes", p.RequiredAdditionalBytes).Int("required_reclaim_bytes", p.RequiredReclaimBytes).
			Int("soft_fair_share_bytes", p.FairShareBytes).Int("scanned_participants", p.ScannedParticipants).
			Int("victim_retained_bytes", p.VictimRetainedBytes).Int("victim_queued_retained_bytes", p.VictimQueuedBytes).
			Int("victim_inflight_retained_bytes", p.VictimInflightBytes).Int("victim_output_retained_bytes", p.VictimOutputBytes).
			Int("victim_output_unread_bytes", p.VictimUnreadBytes).Str("victim_output_wait", p.VictimWait.String()).
			Bool("victim_observation_available", p.VictimObservationAvailable).Bool("victim_progress_available", p.VictimProgressAvailable).
			Int("reclaimed_retained_bytes", p.ReclaimedBytes)
		if p.VictimObservationAvailable {
			event.Dur("victim_observation_age_ms", p.VictimObservationAge)
		}
		if p.VictimProgressAvailable {
			event.Dur("victim_progress_age_ms", p.VictimProgressAge)
		}
	}
	for _, queue := range []struct {
		name  string
		value middleend.ResponseQueueDiagnostic
	}{
		{"incoming", p.Incoming}, {"victim", p.Victim}, {"slot", p.Slot}, {"manager", p.Manager},
	} {
		event.Int(queue.name+"_response_items", queue.value.Items).Int(queue.name+"_response_bytes", queue.value.Bytes)
		if p.Limit != middleend.ResponsePressureSharedBudget {
			event.Int(queue.name+"_response_limit_items", queue.value.ItemLimit).Int(queue.name+"_response_limit_bytes", queue.value.ByteLimit)
		}
	}
	event.Msg("Middle-End response pressure evicted a client binding")
}
