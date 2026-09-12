package webproxy

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// Execute the rendered scripts, not a second implementation of their logic.
// Node is test-only; the bridge and the Telego binary have no new dependency.
func TestBridgeBoundedIO(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatal("Node.js 24 is required for bridge tests in CI")
		}
		t.Skip("install Node.js 24 to run the bridge JavaScript tests")
	}
	dir := t.TempDir()
	token, _, err := newToken()
	if err != nil {
		t.Fatal(err)
	}
	for _, carrier := range []CarrierMode{CarrierHTTPS, CarrierHTTPSLanes, CarrierWebSocket, CarrierWebSocketLanes} {
		page, err := RenderBridgeForCarrier("proxy.example.com", token, maxCarrierBatchBytes, carrier)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, string(carrier)+".html"), page.Body, 0o600); err != nil {
			t.Fatal(err)
		}
		page, err = RenderBridgeForCarrier("proxy.example.com", token, 16, carrier)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, string(carrier)+".small.html"), page.Body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	// Keep one process so the context deadline also stops a stuck test runner.
	cmd := exec.CommandContext(ctx, node, "--max-old-space-size=64", "--test", "--test-isolation=none",
		"--test-timeout=10000", "--test-reporter=tap", "testdata/bridge_io_test.cjs")
	cmd.Env = append(os.Environ(), "TELEGO_BRIDGE_FIXTURES="+dir)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("bridge JavaScript tests: %v\n%s", err, output)
	} else {
		t.Logf("%s", output)
	}
}
