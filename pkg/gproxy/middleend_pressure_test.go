package gproxy

import (
	"context"
	"testing"
	"time"

	"github.com/panjf2000/gnet/v2"

	"github.com/scratch-net/telego/pkg/transport/middleend"
)

func TestResponsePressureCapturesOwnerOutputWithoutClosingSharedLink(t *testing.T) {
	for _, closing := range []bool{false, true} {
		t.Run(map[bool]string{false: "terminal", true: "close_callback"}[closing], func(t *testing.T) {
			link := newMiddleEndTestLink()
			link.autoPong = true
			limits := middleEndTestLimits()
			limits.MaxPendingResponseItemsPerBinding = 1
			manager := newUnstartedMiddleEndTestManager(t, 2, link, limits)
			supervisor, err := middleend.NewFixedBindingGenerationSupervisor(middleend.GenerationSupervisorConfig{
				PreparationTimeout: time.Second, ProbeInterval: time.Hour, ProbeFailureTimeout: 2 * time.Hour,
				RepairBackoffInitial: time.Millisecond, RepairBackoffMaximum: time.Second,
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = supervisor.Close() })
			if err := supervisor.Start(t.Context(), func(context.Context) (*middleend.FixedBindingManager, error) { return manager, nil }); err != nil {
				t.Fatal(err)
			}
			config := middleEndTestFrontendConfig(t, manager)
			config.Source = supervisor
			config.OutputRetryInitial = 10 * time.Second
			config.OutputRetryMax = 10 * time.Second
			config.OutputStallTimeout = time.Minute
			handler, err := NewProxyHandlerWithMiddleEnd(&Config{
				Secrets: []Secret{{Name: "test", Key: []byte("0123456789abcdef"), Host: "example.com"}},
			}, &testLogger{}, config)
			if err != nil {
				t.Fatal(err)
			}
			handler.OnBoot(gnet.Engine{})
			t.Cleanup(func() { handler.OnShutdown(gnet.Engine{}) })
			conn, ctx, _ := commitMiddleEndDDClient(t, handler)
			t.Cleanup(func() { closeMiddleEndTestClient(handler, conn, ctx) })
			conn.SetOutboundBuffered(handler.maxWriteBuffer)
			link.emit(middleend.LinkEvent{Kind: middleend.LinkEventSimpleAck, ConnectionID: ctx.middleEnd.binding.ConnectionID()})
			waitMiddleEndToken(t, ctx.middleEnd)
			if action := runMiddleEndOwner(conn, func() gnet.Action { return handler.OnTraffic(conn) }); action != gnet.None {
				t.Fatalf("blocked output action = %v", action)
			}
			link.emit(middleend.LinkEvent{Kind: middleend.LinkEventSimpleAck, ConnectionID: ctx.middleEnd.binding.ConnectionID()})
			deadline := time.Now().Add(3 * time.Second)
			for supervisor.Snapshot().ResponsePressureEvictions[middleend.ResponsePressureBindingItems] == 0 && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if supervisor.Snapshot().ResponsePressureEvictions[middleend.ResponsePressureBindingItems] != 1 {
				t.Fatal("response burst did not evict the blocked client")
			}
			if !closing {
				if action := runMiddleEndOwner(conn, func() gnet.Action { return handler.OnTraffic(conn) }); action != gnet.Close {
					t.Fatalf("evicted client action = %v", action)
				}
			}
			closeMiddleEndTestClient(handler, conn, ctx)
			records := supervisor.DiagnosticSnapshot().Records
			if len(records) != 2 || records[1].Kind != middleend.GenerationDiagnosticResponsePressureOutput {
				t.Fatalf("expected one eviction and one output observation: %+v", records)
			}
			o := records[1].PressureOutput
			if o.Closing != closing || o.BufferedAvailable == closing || o.AccountedBytes != int64(handler.maxWriteBuffer) ||
				o.Wait != middleend.ResponseOutputClientBuffer || o.WaitSince.IsZero() || !o.RetryPending || o.Web ||
				(!closing && o.BufferedBytes != handler.maxWriteBuffer) {
				t.Fatalf("owner output evidence = %+v", o)
			}
			if records[0].Pressure != records[1].Pressure || !records[0].Pressure.ReadyLeased ||
				supervisor.Snapshot().SlotFailures != 0 || manager.Snapshot().Slots[0].Failed || conn.ownerFault.Load() {
				t.Fatal("diagnostics changed link behavior, lost correlation, or accessed buffers outside the owner")
			}
		})
	}
}
