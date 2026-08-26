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
	for _, forbidden := range []string{"WebSocket(", "webSocketTarget", "tproxy-v1.", "tproxy-lane-v1."} {
		if strings.Contains(body, forbidden) {
			t.Errorf("HTTPS lanes bridge retained dormant WebSocket code %q", forbidden)
		}
	}
	if strings.Contains(page.CSP, "wss:") || !strings.Contains(page.CSP, "connect-src 'self'") {
		t.Fatalf("HTTPS lanes CSP changed: %q", page.CSP)
	}
}

func TestRenderBridgeWebSocketCarrierImplementations(t *testing.T) {
	token, _, err := newToken()
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		carrier  CarrierMode
		protocol string
	}{
		{carrier: CarrierWebSocket, protocol: "'tproxy-v1.'+sessionToken"},
		{carrier: CarrierWebSocketLanes, protocol: "'tproxy-lane-v1.'+sessionToken+'.'+lane.id"},
	} {
		t.Run(string(test.carrier), func(t *testing.T) {
			page, renderErr := RenderBridgeForCarrier("proxy.example.com", token, maxCarrierBatchBytes, test.carrier)
			if renderErr != nil {
				t.Fatal(renderErr)
			}
			body := string(page.Body)
			for _, required := range []string{
				`carrier="` + string(test.carrier) + `"`,
				`webSocketTarget="wss://proxy.example.com/api/v1/ws"`,
				"new WebSocket(webSocketTarget," + test.protocol + ")",
				"socket.binaryType='arraybuffer'",
				"event.data instanceof ArrayBuffer",
				"if(carrier==='websocket')await openWebSocket()",
				"webSocket.send(batch.body)",
				"webSocket.bufferedAmount+queuedBytes>queueByteLimit",
				"socket.onclose=()=>{if(!closed)fail()}",
				"function openWebSocketLane(lane)",
				"function runWebSocketLaneUp(lane)",
				"if(!lane.socket)openWebSocketLane(lane)",
				"finishWebSocketLane(lane,!lane.localClosed&&!lane.remoteClosed)",
				"laneQueueLimit=8388608,laneItemLimit=1024",
				"if(!lane.opened){fail();return}",
			} {
				if !strings.Contains(body, required) {
					t.Errorf("%s bridge omitted %q", test.carrier, required)
				}
			}
			if strings.Contains(body, "new WebSocket(webSocketTarget,{headers:") {
				t.Fatal("WebSocket constructor added request headers")
			}
			if !strings.Contains(page.CSP, "connect-src 'self' wss://proxy.example.com") {
				t.Fatalf("WebSocket CSP = %q", page.CSP)
			}
		})
	}
}

func TestRenderBridgeWebSocketLanesUsesConfiguredStreamLimit(t *testing.T) {
	token, _, err := newToken()
	if err != nil {
		t.Fatal(err)
	}
	page, err := renderBridgeForCarrier(
		"proxy.example.com",
		token,
		maxCarrierBatchBytes,
		CarrierWebSocketLanes,
		2,
	)
	if err != nil {
		t.Fatal(err)
	}
	body := string(page.Body)
	if !strings.Contains(body, "maxWebSocketLanes=2") {
		t.Fatal("WebSocket lanes bridge omitted the configured session stream limit")
	}
	bufferedStart := strings.Index(body, "function bufferedBytes(lane){")
	bufferedEnd := strings.Index(body, "function refreshAllWebSocketBuffered(){")
	capacityStart := strings.Index(body, "function hasWebSocketByteCapacity(data,lane){")
	capacityEnd := strings.Index(body, "function reserve(data,lane){")
	if bufferedStart < 0 || bufferedEnd <= bufferedStart || capacityStart <= bufferedEnd || capacityEnd <= capacityStart {
		t.Fatal("WebSocket buffered-byte accounting functions are missing")
	}
	if strings.Contains(body[bufferedStart:bufferedEnd], "lanes.values()") {
		t.Fatal("steady-path WebSocket lane reservation scans every active lane")
	}
	if !strings.Contains(body[bufferedEnd:capacityStart],
		"for(const activeLane of lanes.values())refreshWebSocketBuffered(activeLane.socket,activeLane)") {
		t.Fatal("near-limit WebSocket reservation does not refresh stale sibling lanes")
	}
	capacity := body[capacityStart:capacityEnd]
	fastAccept := strings.Index(capacity,
		"if(queuedBytes+bufferedBytes(lane)<=queueByteLimit-data.byteLength)return true")
	slowRefresh := strings.Index(capacity,
		"queuedBytes+refreshAllWebSocketBuffered()<=queueByteLimit-data.byteLength")
	if fastAccept < 0 || slowRefresh <= fastAccept {
		t.Fatalf("WebSocket reservation does not keep refresh on the rejection slow path: fast=%d slow=%d",
			fastAccept, slowRefresh)
	}
	queueStart := strings.Index(body, "function queueWebSocketLane(frame){")
	queueEnd := strings.Index(body, "function scheduleWebSocketLaneUp(lane){")
	if queueStart < 0 || queueEnd <= queueStart {
		t.Fatal("WebSocket lane queue implementation is missing")
	}
	queue := body[queueStart:queueEnd]
	guard := strings.Index(queue, "webSocketLaneReservations>=maxWebSocketLanes")
	reservation := strings.Index(queue, "webSocketLaneReservations++;lane=ensureLane(frame.id)")
	byteReservation := strings.Index(queue, "if(!reserve(frame.data,lane))")
	construction := strings.Index(queue, "if(!lane.socket)openWebSocketLane(lane)")
	if guard < 0 || reservation <= guard || byteReservation <= reservation || construction <= byteReservation {
		t.Fatalf("WebSocket lane limit order is unsafe: guard=%d lane=%d bytes=%d socket=%d",
			guard, reservation, byteReservation, construction)
	}
}

func TestRenderedBridgeWebSocketReservationRefreshesStaleSiblingAtLimit(t *testing.T) {
	const limit = 32 * 1024 * 1024
	token, _, err := newToken()
	if err != nil {
		t.Fatal(err)
	}
	page, err := renderBridgeForCarrier(
		"proxy.example.com",
		token,
		maxCarrierBatchBytes,
		CarrierWebSocketLanes,
		2,
	)
	if err != nil {
		t.Fatal(err)
	}
	if body := string(page.Body); !strings.Contains(body,
		"if(queuedBytes+bufferedBytes(lane)<=queueByteLimit-data.byteLength)return true;\n"+
			" return queuedBytes+refreshAllWebSocketBuffered()<=queueByteLimit-data.byteLength;") {
		t.Fatal("rendered WebSocket bridge omitted the tested fast/refresh reservation branches")
	}

	reservationAllowed := func(queued, tracked, data int, actual []int) bool {
		if queued+tracked <= limit-data {
			return true
		}
		actualTotal := 0
		for _, buffered := range actual {
			actualTotal += buffered
		}
		return queued+actualTotal <= limit-data
	}

	if !reservationAllowed(0, limit-1, 2, []int{0, 0}) {
		t.Fatal("slow-path refresh rejected a new lane after its stale sibling drained")
	}
	if !reservationAllowed(1024, limit-1, 2048, []int{0, limit - 4096}) {
		t.Fatal("slow-path refresh rejected an existing lane message after its sibling drained")
	}
	if reservationAllowed(1024, limit-1, 2048, []int{limit - 2048}) {
		t.Fatal("slow-path refresh accepted a truly over-limit reservation")
	}
}

func TestRenderedBridgeWebSocketClosingLaneRetainsBufferedOwnership(t *testing.T) {
	const limit = 32 * 1024 * 1024
	token, _, err := newToken()
	if err != nil {
		t.Fatal(err)
	}
	page, err := renderBridgeForCarrier(
		"proxy.example.com",
		token,
		maxCarrierBatchBytes,
		CarrierWebSocketLanes,
		2,
	)
	if err != nil {
		t.Fatal(err)
	}
	body := string(page.Body)
	refreshStart := strings.Index(body, "function refreshWebSocketBuffered(socket,lane){")
	refreshEnd := strings.Index(body, "function bufferedBytes(lane){")
	finishStart := strings.Index(body, "function finishWebSocketLane(lane,notify){")
	finishEnd := strings.Index(body, "function openWebSocketLane(lane){")
	if refreshStart < 0 || refreshEnd <= refreshStart || finishStart < 0 || finishEnd <= finishStart {
		t.Fatal("rendered WebSocket ownership functions are missing")
	}
	refresh := body[refreshStart:refreshEnd]
	if !strings.Contains(refresh, "const current=socket?socket.bufferedAmount:0") ||
		strings.Contains(refresh, "readyState===WebSocket.OPEN") {
		t.Fatal("closing WebSocket buffered bytes are released before onclose finalization")
	}
	finish := body[finishStart:finishEnd]
	for _, required := range []string{
		"if(lane.finished||lanes.get(lane.id)!==lane)return",
		"lane.finished=true;if(lane.timer)clearTimeout(lane.timer)",
		"webSocketBufferedBytes-=lane.buffered;lane.buffered=0;webSocketLaneReservations--",
	} {
		if !strings.Contains(finish, required) {
			t.Fatalf("WebSocket lane finalizer omitted %q", required)
		}
	}
	for _, required := range []string{
		"webSocket.readyState!==WebSocket.OPEN)return",
		"socket.readyState!==WebSocket.OPEN)return",
	} {
		if !strings.Contains(body, required) {
			t.Fatalf("WebSocket send path omitted OPEN guard %q", required)
		}
	}

	aggregate, tracked := 0, 0
	finished := false
	refreshBuffered := func(actual int) {
		aggregate += actual - tracked
		tracked = actual
	}
	finishLane := func() {
		if finished {
			return
		}
		finished = true
		aggregate -= tracked
		tracked = 0
	}
	canReserve := func(queued, data int) bool {
		return queued+aggregate <= limit-data
	}

	refreshBuffered(limit - 2048)
	if canReserve(1024, 2048) {
		t.Fatal("closing sibling released buffered-byte ownership before onclose")
	}
	finishLane()
	if !canReserve(1024, 2048) {
		t.Fatal("onclose finalization did not release buffered-byte ownership")
	}
	finishLane()
	if aggregate != 0 || tracked != 0 {
		t.Fatalf("duplicate lane finalization underflowed ownership: aggregate=%d tracked=%d", aggregate, tracked)
	}
}

func TestRenderBridgeWebSocketUsesExactRequestHost(t *testing.T) {
	token, _, err := newToken()
	if err != nil {
		t.Fatal(err)
	}
	for _, authority := range []string{
		"proxy.example.com",
		"proxy.example.com:8443",
		"127.0.0.1",
		"127.0.0.1:443",
		"[2001:db8::1]",
		"[2001:db8::1]:8443",
	} {
		t.Run(authority, func(t *testing.T) {
			page, renderErr := RenderBridgeForCarrier(authority, token, 1024, CarrierWebSocket)
			if renderErr != nil {
				t.Fatal(renderErr)
			}
			body := string(page.Body)
			if !strings.Contains(body, `relayOrigin="https://`+authority+`"`) ||
				!strings.Contains(body, `webSocketTarget="wss://`+authority+webSocketPath+`"`) {
				t.Fatalf("bridge did not preserve request host %q", authority)
			}
			if !strings.Contains(page.CSP, "connect-src 'self' wss://"+authority) {
				t.Fatalf("CSP did not preserve request host %q: %q", authority, page.CSP)
			}
		})
	}
}

func TestRenderBridgeWebSocketRejectsInvalidRequestHost(t *testing.T) {
	token, _, err := newToken()
	if err != nil {
		t.Fatal(err)
	}
	for _, authority := range []string{
		"Proxy.example.com",
		"proxy.example.com:0",
		"proxy.example.com:0443",
		"proxy.example.com:65536",
		"proxy.example.com/path",
		"user@proxy.example.com",
		"2001:db8::1",
		"[2001:0db8::1]",
		"[fe80::1%25eth0]",
	} {
		t.Run(authority, func(t *testing.T) {
			if _, renderErr := RenderBridgeForCarrier(authority, token, 1024, CarrierWebSocket); renderErr == nil {
				t.Fatal("RenderBridgeForCarrier accepted an invalid request host")
			}
		})
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
		"stream limit": func() error {
			_, renderErr := renderBridgeForCarrier("proxy.example.com", token, 1024, CarrierWebSocketLanes, 0)
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
