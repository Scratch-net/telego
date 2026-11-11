package middleend

import (
	"context"
	"errors"
	"testing"
	"time"
)

// An unexpected gnet client exit closes RuntimeDone with an error, so the
// process owner can exit and let its supervisor restart Middle-End.
func TestServiceRuntimeFailureReportsUnexpectedExit(t *testing.T) {
	runtime, err := NewGnetClientRuntime(GnetClientRuntimeConfig{EventLoops: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Stop(context.Background()) })
	service := &Service{state: &serviceState{runtime: runtime}}
	select {
	case <-service.RuntimeDone():
		t.Fatal("RuntimeDone closed while the runtime runs")
	default:
	}
	if err := runtime.client.Stop(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-service.RuntimeDone():
	case <-time.After(5 * time.Second):
		t.Fatal("RuntimeDone did not close after the client exit")
	}
	if err := service.RuntimeErr(); !errors.Is(err, ErrGnetRuntimeStopped) {
		t.Fatalf("RuntimeErr = %v, want ErrGnetRuntimeStopped", err)
	}
}

func TestServiceRuntimeDoneNilService(t *testing.T) {
	var service *Service
	if service.RuntimeDone() != nil {
		t.Fatal("nil service must return a nil channel")
	}
	if err := service.RuntimeErr(); err != nil {
		t.Fatalf("RuntimeErr = %v", err)
	}
}
