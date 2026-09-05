package gproxy

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/panjf2000/gnet/v2"
	errorx "github.com/panjf2000/gnet/v2/pkg/errors"

	"github.com/scratch-net/telego/pkg/transport/middleend"
	"github.com/scratch-net/telego/pkg/transport/obfuscated2"
	"github.com/scratch-net/telego/pkg/webproxy"
)

type logicalWebTest struct {
	manager  *webproxy.Manager
	server   *webproxy.HTTPServer
	client   *http.Client
	address  string
	token    string
	sequence uint64
	cursor   string
	streams  chan *LogicalStream
}

func startLogicalWeb(t *testing.T, handler *ProxyHandler) *logicalWebTest {
	t.Helper()
	key := handler.config.Secrets[0].Key
	profiles, err := webproxy.DeriveProfiles("logical", "proxy.example.com", key)
	if err != nil {
		t.Fatal(err)
	}
	x := &logicalWebTest{client: &http.Client{Timeout: 4 * time.Second}, cursor: "0", streams: make(chan *LogicalStream, 1)}
	config := webproxy.DefaultManagerConfig(profiles[:], "")
	config.Timeouts.LongPoll = 50 * time.Millisecond
	config.BackendFactory = func(options webproxy.BackendOpenOptions) (webproxy.Backend, error) {
		address, err := netip.ParseAddr(options.ClientIP)
		if err != nil {
			return nil, err
		}
		stream, err := handler.OpenLogicalStream(LogicalStreamOptions{
			Owner: options.Owner, ClientAddr: netip.AddrPortFrom(address, 0),
			LocalAddr:     &net.TCPAddr{IP: net.IPv4zero, Port: 443},
			MaxInputBytes: options.MaxInputBytes, MaxInputItems: options.MaxInputItems,
			MaxOutputBytes: options.MaxOutputBytes, MaxOutputItems: options.MaxOutputItems,
			InputBudget:  LogicalQueueBudget{Reserve: options.InputBudget.Reserve, Release: options.InputBudget.Release},
			OutputBudget: LogicalQueueBudget{Reserve: options.OutputBudget.Reserve, Release: options.OutputBudget.Release},
			Notify:       options.Notify, OnOpened: options.OnOpened, OnClosed: options.OnClosed,
		})
		if err == nil {
			x.streams <- stream
		}
		return stream, err
	}
	x.manager, err = webproxy.NewManager(config)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	x.address = listener.Addr().String()
	_ = listener.Close()
	x.server, err = webproxy.NewHTTPServer(webproxy.HTTPServerConfig{Bind: x.address, Hostname: "proxy.example.com", Manager: x.manager, NumEventLoop: 2})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		if err := x.manager.Shutdown(ctx); err != nil {
			t.Errorf("WEB manager cleanup: %v", err)
		}
		if err := x.server.Stop(ctx); err != nil {
			t.Errorf("WEB engine cleanup: %v", err)
		}
		if capacity := x.manager.Capacity(); capacity.PendingBytes != 0 || capacity.PendingItems != 0 || capacity.Streams != 0 || capacity.BackendDials != 0 {
			t.Errorf("WEB logical cleanup retained resources: %+v", capacity)
		}
	})
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	if err := x.server.Start(ctx); err != nil {
		t.Fatal(err)
	}
	bootstrap, err := x.manager.IssueBootstrap(profiles[0].Capability(), "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	hello, err := webproxy.EncodeFrame(webproxy.Frame{Type: webproxy.FrameHello, Payload: []byte{1}})
	if err != nil {
		t.Fatal(err)
	}
	response, _ := x.request(t, "/api/v1/session", hello, map[string]string{"Authorization": "Bearer " + bootstrap, "Content-Type": "application/octet-stream"})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("WEB CREATE: %d", response.StatusCode)
	}
	x.token = response.Header.Get("X-Session-Token")
	return x
}

func (x *logicalWebTest) request(t *testing.T, path string, body []byte, headers map[string]string) (*http.Response, []byte) {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), "POST", "http://"+x.address+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Host = "proxy.example.com"
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	response, err := x.client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response, data
}

func (x *logicalWebTest) upload(t *testing.T, payload []byte, open bool) {
	t.Helper()
	var frames []byte
	var err error
	if open {
		frames, err = webproxy.AppendFrame(frames, webproxy.Frame{Type: webproxy.FrameOpen, StreamID: 1})
		if err != nil {
			t.Fatal(err)
		}
	}
	frames, err = webproxy.AppendFrame(frames, webproxy.Frame{Type: webproxy.FrameData, StreamID: 1, Payload: payload})
	if err != nil {
		t.Fatal(err)
	}
	x.sequence++
	response, _ := x.request(t, "/api/v1/up", frames, map[string]string{
		"Authorization": "Bearer " + x.token, "Content-Type": "application/octet-stream", "X-Up-Seq": strconv.FormatUint(x.sequence, 10),
	})
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("WEB UP: %d", response.StatusCode)
	}
}

func (x *logicalWebTest) download(t *testing.T, size int) []byte {
	t.Helper()
	var output []byte
	deadline := time.Now().Add(4 * time.Second)
	for len(output) < size {
		if time.Now().After(deadline) {
			t.Fatalf("WEB downlink stalled at %d/%d", len(output), size)
		}
		response, body := x.request(t, "/api/v1/down", nil, map[string]string{"Authorization": "Bearer " + x.token, "X-Down-Cursor": x.cursor})
		if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusNoContent {
			t.Fatalf("WEB DOWN: %d", response.StatusCode)
		}
		x.cursor = response.Header.Get("X-Down-Cursor")
		if len(body) == 0 {
			continue
		}
		frames, err := webproxy.ParseBatch(body)
		if err != nil {
			t.Fatal(err)
		}
		for _, frame := range frames {
			if frame.Type == webproxy.FrameClose {
				t.Fatal("WEB stream closed before its response")
			}
			if frame.Type == webproxy.FrameData {
				output = append(output, frame.Payload...)
			}
		}
	}
	return output
}

func TestLogicalWebHTTPDirectComposition(t *testing.T) {
	key := []byte("0123456789abcdef")
	handler := NewProxyHandler(&Config{Secrets: []Secret{{Name: "logical", Key: key, Host: "example.com"}}, TimeSkewTolerance: time.Minute}, &testLogger{})
	dc, socket := directTCPPair(t)
	startLogicalDC(t, handler, socket)
	web := startLogicalWeb(t, handler)
	frame := buildDeterministicO2ClientFrame(t, key, 2, obfuscated2.ConnectionTypeIntermediate)
	_, _, responseCipher, requestCipher, err := obfuscated2.ParseClientFrameWithType(key, frame)
	if err != nil {
		t.Fatal(err)
	}
	request := bytes.Repeat([]byte("WEB to shared direct core"), 2000)
	wire := make([]byte, len(request))
	requestCipher.XORKeyStream(wire, request)
	web.upload(t, append(bytes.Clone(frame), wire...), true)
	stream := <-web.streams
	if err := dc.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(request))
	if _, err := io.ReadFull(dc, got); err != nil {
		t.Fatal(err)
	}
	directTestCipher(t, 2).XORKeyStream(got, got)
	if !bytes.Equal(got, request) {
		t.Fatal("WEB client bytes changed through native authentication/direct relay")
	}
	response := bytes.Repeat([]byte("shared core response"), 1000)
	dcWire := make([]byte, len(response))
	directTestCipher(t, 3).XORKeyStream(dcWire, response)
	if _, err := dc.Write(dcWire); err != nil {
		t.Fatal(err)
	}
	got = web.download(t, len(response))
	responseCipher.XORKeyStream(got, got)
	if !bytes.Equal(got, response) {
		t.Fatal("WEB downlink changed through direct relay")
	}
	runLogicalOwner(t, stream.options.Owner, func() {
		if stream.ctx.State() != StateRelaying || stream.ctx.RealClientAddr(nil).String() != "127.0.0.1:0" {
			t.Error("logical stream did not use native admission and trusted client metadata")
		}
	})
}

func TestLogicalWebHTTPFatalOwnerRetiresAcceptedClose(t *testing.T) {
	key := []byte("0123456789abcdef")
	handler := NewProxyHandler(&Config{Secrets: []Secret{{Name: "logical", Key: key, Host: "example.com"}}, TimeSkewTolerance: time.Minute}, &testLogger{})
	web := startLogicalWeb(t, handler)
	web.upload(t, []byte{0xef}, true)
	stream := <-web.streams
	entered, release := make(chan struct{}), make(chan struct{})
	if err := stream.options.Owner.Execute(t.Context(), gnet.RunnableFunc(func(context.Context) error {
		close(entered)
		<-release
		return errorx.ErrEngineShutdown
	})); err != nil {
		t.Fatal(err)
	}
	<-entered
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	if err := web.manager.Close(web.token); err != nil {
		t.Fatal(err)
	}
	close(release)
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	if err := web.server.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if err := web.manager.Shutdown(ctx); err != nil {
		t.Fatalf("accepted but abandoned logical close stranded WEB shutdown: %v", err)
	}
	if capacity := web.manager.Capacity(); capacity.PendingBytes != 0 || capacity.PendingItems != 0 || capacity.Streams != 0 || capacity.BackendDials != 0 {
		t.Fatalf("retired owner retained logical resources: %+v", capacity)
	}
}

func TestLogicalWebCanAuthenticateBeforePublicListenerStarts(t *testing.T) {
	key := []byte("0123456789abcdef")
	handler := NewProxyHandler(&Config{Secrets: []Secret{{Name: "logical", Key: key, Host: "example.com"}}, TimeSkewTolerance: time.Minute}, &testLogger{})
	_, socket := directTCPPair(t)
	engine, err := gnet.NewClient(&dcEventHandler{proxy: handler})
	if err != nil {
		t.Fatal(err)
	}
	monitorDone, err := handler.startDCClient(engine, func(err error) { t.Errorf("unexpected DC failure: %v", err) })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = handler.stopDCClient(); <-monitorDone })
	if handler.dcClient != engine {
		t.Fatal("startup returned without publishing the initialized DC owner")
	}
	handler.directDCDial = func(context.Context, int, obfuscated2.ConnectionType) (*directDCConn, error) {
		return &directDCConn{Conn: socket, encryptor: directTestCipher(t, 2), decryptor: directTestCipher(t, 3)}, nil
	}
	// There is deliberately no public engine or OnBoot call. The first WEB
	// request must work after synchronous DC setup alone, without a delay.
	web := startLogicalWeb(t, handler)
	web.upload(t, buildDeterministicO2ClientFrame(t, key, 2, obfuscated2.ConnectionTypeIntermediate), true)
	stream := <-web.streams
	_ = awaitDirectRelay(t, stream.ctx)
}

func TestLogicalWebFailsClosedAfterDCStartupFailure(t *testing.T) {
	key := []byte("0123456789abcdef")
	handler := NewProxyHandler(&Config{Secrets: []Secret{{Name: "logical", Key: key, Host: "example.com"}}, TimeSkewTolerance: time.Minute}, &testLogger{})
	engine, err := gnet.NewClient(&gnet.BuiltinEventEngine{})
	if err != nil {
		t.Fatal(err)
	}
	// The dependency explicitly rejects Start after Stop. This deterministic
	// startup failure does not depend on allocation failure or event timing.
	if err := engine.Stop(); err != nil {
		t.Fatal(err)
	}
	monitorDone, err := handler.startDCClient(engine, nil)
	t.Cleanup(func() {
		_ = handler.stopDCClient()
		if monitorDone != nil {
			<-monitorDone
		}
	})
	if err == nil || monitorDone != nil || handler.dcClient != nil {
		t.Fatalf("failed startup published owner or monitor: client=%t monitor=%t err=%v", handler.dcClient != nil, monitorDone != nil, err)
	}
	select {
	case <-engine.Done():
	default:
		t.Fatal("startup failure returned before DC cleanup")
	}
	web := startLogicalWeb(t, handler)
	web.upload(t, buildDeterministicO2ClientFrame(t, key, 2, obfuscated2.ConnectionTypeIntermediate), true)
	stream := <-web.streams
	awaitSpliceCondition(t, "failed-startup logical close", func() bool {
		return stream.ctx.State() == StateClosed && web.manager.Capacity().Streams == 0
	})
}

func TestLogicalWebHTTPMiddleEndBeforePublicListenerStarts(t *testing.T) {
	key := []byte("0123456789abcdef")
	link := newMiddleEndTestLink()
	manager := newMiddleEndTestManager(t, 2, link)
	handler, err := NewProxyHandlerWithMiddleEnd(&Config{
		Secrets:           []Secret{{Name: "test", Key: key, Host: "example.com"}},
		TimeSkewTolerance: time.Minute,
	}, &testLogger{}, middleEndTestFrontendConfig(t, manager))
	if err != nil {
		t.Fatal(err)
	}
	// Publication preparation must start the exclusive readiness consumer:
	// no public engine or OnBoot callback participates in this exchange.
	handler.prepareFrontends()
	t.Cleanup(func() { _ = handler.stopServing() })
	frame := buildDeterministicO2ClientFrame(t, key, 2, obfuscated2.ConnectionTypeIntermediate)
	web := startLogicalWeb(t, handler)
	_, _, responseCipher, requestCipher, err := obfuscated2.ParseClientFrameWithType(key, frame)
	if err != nil {
		t.Fatal(err)
	}
	packet := validMiddleEndPacket()
	wire := encodeMiddleEndClientPacket(t, obfuscated2.ConnectionTypeIntermediate, packet, requestCipher)
	web.upload(t, append(bytes.Clone(frame), wire...), true)
	stream := <-web.streams
	request, err := middleend.ParseProxyRequest(waitMiddleEndSubmission(t, link).Payload)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(request.Packet, packet) {
		t.Fatal("WEB packet changed through shared ME admission")
	}
	var id int64
	runLogicalOwner(t, stream.options.Owner, func() { id = stream.ctx.middleEnd.binding.ConnectionID() })
	answer := append(validMiddleEndPacket(), 1, 2, 3, 4)
	link.emit(middleend.LinkEvent{Kind: middleend.LinkEventProxyAnswer, ConnectionID: id, Packet: bytes.Clone(answer)})
	got := web.download(t, 4+len(answer))
	responseCipher.XORKeyStream(got, got)
	if binary.LittleEndian.Uint32(got[:4]) != uint32(len(answer)) || !bytes.Equal(got[4:], answer) {
		t.Fatal("WEB ME reply lost cipher state or packet framing")
	}
}
