package webproxy

import (
	"strings"
	"testing"
)

func TestRenderBridgeHTTPSContractAndSecurityHeaders(t *testing.T) {
	token, _, err := newToken()
	if err != nil {
		t.Fatal(err)
	}
	page, err := RenderBridge("proxy.example.com", token, 2*1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	body := string(page.Body)
	if !strings.Contains(body, `carrier="https"`) {
		t.Fatal("serialized bridge omitted its carrier mode")
	}
	for _, required := range []string{
		`nonce="` + page.Nonce + `"`,
		`bootstrap="` + token + `"`,
		`history.replaceState(null,'',location.pathname)`,
		`globalThis.TelegramWebProxy`,
		`tproxy-android-init`,
		`tproxy-init`,
		`event.source!==parent`,
		`source.hostname!=='127.0.0.1'`,
		`/api/v1/session`,
		`/api/v1/up`,
		`/api/v1/down`,
		`X-Up-Seq`,
		`X-Up-Ack`,
		`X-Down-Cursor`,
		`Retry-After`,
		`queueByteLimit=33554432`,
		`queueItemLimit=16384`,
		`maxFrames=4096`,
		`credentials:'omit'`,
		`cache:'no-store'`,
		`redirect:'error'`,
		`referrerPolicy:'no-referrer'`,
		`port.postMessage(welcome,[welcome])`,
		`deleteSession()`,
		`lifecycleController=new AbortController()`,
		`ensureOpen(external)`,
		`const remaining=deadline-Date.now()`,
		`setTimeout(abort,remaining)`,
		`const backoffRemaining=deadline-Date.now()`,
		`Math.min(retry||`,
		`await pause(backoff,external)`,
		`lifecycleController.abort()`,
	} {
		if !strings.Contains(body, required) {
			t.Errorf("bridge omitted %q", required)
		}
	}
	for _, forbidden := range []string{
		"WebSocket(",
		"localStorage",
		"sessionStorage",
		"indexedDB",
		"document.cookie",
		"__NONCE__",
		"__BOOTSTRAP__",
		"__CARRIER__",
		"__BATCH_LIMIT__",
	} {
		if strings.Contains(body, forbidden) {
			t.Errorf("bridge retained forbidden value %q", forbidden)
		}
	}
	for _, directive := range []string{
		"default-src 'none'",
		"connect-src 'self'",
		"frame-ancestors http://127.0.0.1:*",
		"script-src 'nonce-" + page.Nonce + "'",
		"worker-src 'none'",
		"sandbox allow-same-origin allow-scripts",
	} {
		if !strings.Contains(page.CSP, directive) {
			t.Errorf("CSP omitted %q", directive)
		}
	}
	if strings.Contains(page.CSP, "wss:") || strings.Contains(page.CSP, "'unsafe-inline'") {
		t.Fatalf("HTTPS-only CSP grants an unused capability: %q", page.CSP)
	}
	if !strings.Contains(PermissionsPolicy, "camera=()") || !strings.Contains(PermissionsPolicy, "clipboard-read=()") {
		t.Fatalf("Permissions-Policy is incomplete: %q", PermissionsPolicy)
	}
}

func TestRenderBridgeHTTPSLanesContract(t *testing.T) {
	token, _, err := newToken()
	if err != nil {
		t.Fatal(err)
	}
	page, err := RenderBridgeForCarrier("proxy.example.com", token, 2*1024*1024, CarrierHTTPSLanes)
	if err != nil {
		t.Fatal(err)
	}
	body := string(page.Body)
	for _, required := range []string{
		`carrier="https-lanes"`,
		`X-Lane-ID`,
		`X-Lane-Closed`,
		`lane did not begin with OPEN`,
		`cross-lane frame`,
		`ensureLane(0)`,
	} {
		if !strings.Contains(body, required) {
			t.Errorf("lanes bridge omitted %q", required)
		}
	}
}

func TestRenderBridgeRejectsInvalidInputsAndUsesPerResponseNonce(t *testing.T) {
	token, _, err := newToken()
	if err != nil {
		t.Fatal(err)
	}
	first, err := RenderBridge("proxy.example.com", token, 1024)
	if err != nil {
		t.Fatal(err)
	}
	second, err := RenderBridge("proxy.example.com", token, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if first.Nonce == second.Nonce {
		t.Fatal("bridge reused a CSP nonce")
	}
	for name, call := range map[string]func() error{
		"hostname": func() error {
			_, renderErr := RenderBridge("Proxy.example.com", token, 1024)
			return renderErr
		},
		"token": func() error {
			_, renderErr := RenderBridge("proxy.example.com", "invalid", 1024)
			return renderErr
		},
		"batch zero": func() error {
			_, renderErr := RenderBridge("proxy.example.com", token, 0)
			return renderErr
		},
		"batch over cap": func() error {
			_, renderErr := RenderBridge("proxy.example.com", token, maxCarrierBatchBytes+1)
			return renderErr
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := call(); err == nil {
				t.Fatal("RenderBridge accepted invalid input")
			}
		})
	}
}
