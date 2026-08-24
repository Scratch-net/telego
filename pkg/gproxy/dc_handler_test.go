package gproxy

import (
	"bytes"
	"context"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/panjf2000/gnet/v2"

	"github.com/scratch-net/telego/pkg/dc"
	"github.com/scratch-net/telego/pkg/transport/obfuscated2"
)

type spliceRelayTestHandler struct {
	*ProxyHandler
	upstream  net.Conn
	engine    atomic.Pointer[gnet.Engine]
	ready     chan struct{}
	closed    chan struct{}
	relayDone chan struct{}
	closeOnce sync.Once
}

type spliceReadErrorConn struct {
	net.Conn
	err error
}

func (c *spliceReadErrorConn) Read([]byte) (int, error) { return 0, c.err }

type spliceReadStartedConn struct {
	net.Conn
	started chan struct{}
	once    sync.Once
}

func (c *spliceReadStartedConn) Read(buffer []byte) (int, error) {
	c.once.Do(func() { close(c.started) })
	return c.Conn.Read(buffer)
}

func (h *spliceRelayTestHandler) OnBoot(engine gnet.Engine) gnet.Action {
	h.engine.Store(&engine)
	close(h.ready)
	return gnet.None
}

func (h *spliceRelayTestHandler) OnOpen(connection gnet.Conn) ([]byte, gnet.Action) {
	ctx := NewConnContext()
	ctx.SetState(StateSplicing)
	ctx.SetSpliceConn(h.upstream)
	connection.SetContext(ctx)
	atomic.AddInt64(&h.activeConns, 1)
	go func() {
		h.relaySpliceToClientLoop(h.upstream, connection, ctx)
		close(h.relayDone)
	}()
	return nil, gnet.None
}

func (h *spliceRelayTestHandler) OnClose(connection gnet.Conn, err error) gnet.Action {
	action := h.ProxyHandler.OnClose(connection, err)
	h.closeOnce.Do(func() { close(h.closed) })
	return action
}

func runSpliceRelayTestServer(t *testing.T, upstream net.Conn) (*spliceRelayTestHandler, string) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	handler := &spliceRelayTestHandler{
		ProxyHandler: NewProxyHandler(&Config{
			SpliceIdleTimeout: 30 * time.Second,
			MaxWriteBuffer:    4 * 1024 * 1024,
		}, &testLogger{}),
		upstream:  upstream,
		ready:     make(chan struct{}),
		closed:    make(chan struct{}),
		relayDone: make(chan struct{}),
	}
	errCh := make(chan error, 1)
	go func() {
		errCh <- gnet.Run(handler, "tcp://"+address,
			gnet.WithNumEventLoop(1),
			gnet.WithSocketSendBuffer(4096),
			gnet.WithWriteBufferCap(4096),
		)
	}()
	select {
	case <-handler.ready:
	case err := <-errCh:
		t.Fatalf("start splice test server: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out starting splice test server")
	}
	t.Cleanup(func() {
		if engine := handler.engine.Load(); engine != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if err := (*engine).Stop(ctx); err != nil {
				t.Errorf("stop splice test server: %v", err)
			}
		}
		select {
		case err := <-errCh:
			if err != nil {
				t.Errorf("splice test server: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("splice test server did not stop")
		}
	})
	return handler, address
}

func waitForSpliceRelaySignal(t *testing.T, signal <-chan struct{}, name string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for %s", name)
	}
}

func TestRelaySpliceToClientDrainsBeforeClose(t *testing.T) {
	proxyUpstream, backend := net.Pipe()
	defer backend.Close()
	payload := bytes.Repeat([]byte("telego-splice-drain-"), 128*1024)
	writeErr := make(chan error, 1)
	go func() {
		_, err := backend.Write(payload)
		if closeErr := backend.Close(); err == nil {
			err = closeErr
		}
		writeErr <- err
	}()

	handler, address := runSpliceRelayTestServer(t, proxyUpstream)
	connection, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if tcp, ok := connection.(*net.TCPConn); ok {
		if err := tcp.SetReadBuffer(1024); err != nil {
			t.Fatal(err)
		}
	}
	// Keep the receive window constrained while the upstream reaches EOF.
	time.Sleep(100 * time.Millisecond)
	if err := connection.SetReadDeadline(time.Now().Add(20 * time.Second)); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(connection)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("splice payload bytes = %d, want exact %d", len(got), len(payload))
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("write splice payload: %v", err)
	}
	waitForSpliceRelaySignal(t, handler.relayDone, "splice relay exit")
	waitForSpliceRelaySignal(t, handler.closed, "client close")
}

func TestRelaySpliceReadErrorClosesWithoutLeak(t *testing.T) {
	proxyUpstream, backend := net.Pipe()
	defer backend.Close()
	readErr := errors.New("test splice read failure")
	handler, address := runSpliceRelayTestServer(t, &spliceReadErrorConn{Conn: proxyUpstream, err: readErr})
	connection, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	waitForSpliceRelaySignal(t, handler.relayDone, "splice relay exit")
	waitForSpliceRelaySignal(t, handler.closed, "client close")
	if active := atomic.LoadInt64(&handler.activeConns); active != 0 {
		t.Fatalf("active splice connections = %d, want 0", active)
	}
}

func TestRelaySpliceClientCancellationStopsBlockedRead(t *testing.T) {
	proxyUpstream, backend := net.Pipe()
	defer backend.Close()
	started := make(chan struct{})
	upstream := &spliceReadStartedConn{Conn: proxyUpstream, started: started}
	handler, address := runSpliceRelayTestServer(t, upstream)
	connection, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	waitForSpliceRelaySignal(t, started, "splice upstream read")
	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}
	waitForSpliceRelaySignal(t, handler.closed, "client close")
	waitForSpliceRelaySignal(t, handler.relayDone, "splice relay exit")
	if active := atomic.LoadInt64(&handler.activeConns); active != 0 {
		t.Fatalf("active splice connections = %d, want 0", active)
	}
}

func decodeFakeDCHandshake(
	t *testing.T,
	wire []byte,
) (obfuscated2.ConnectionType, int, cipher.Stream, cipher.Stream) {
	t.Helper()

	dcDecryptor, err := obfuscated2.NewAESCTR(wire[8:40], wire[40:56])
	if err != nil {
		t.Fatalf("create fake DC decryptor: %v", err)
	}
	plain := make([]byte, obfuscated2.FrameSize)
	dcDecryptor.XORKeyStream(plain, wire)

	var reversed [48]byte
	for i := range reversed {
		reversed[47-i] = wire[8+i]
	}
	dcEncryptor, err := obfuscated2.NewAESCTR(reversed[:32], reversed[32:48])
	if err != nil {
		t.Fatalf("create fake DC encryptor: %v", err)
	}

	connectionType := obfuscated2.ConnectionType(binary.LittleEndian.Uint32(plain[56:60]))
	dcID := int(int16(binary.LittleEndian.Uint16(plain[60:62])))
	return connectionType, dcID, dcDecryptor, dcEncryptor
}

func TestWriteDCHandshake_PreservesPacketFraming(t *testing.T) {
	tests := []struct {
		name           string
		connectionType obfuscated2.ConnectionType
		packet         []byte
	}{
		{
			name:           "abridged EF",
			connectionType: obfuscated2.ConnectionTypeAbridged,
			packet:         []byte{0x01, 0xde, 0xad, 0xbe, 0xef},
		},
		{
			name:           "intermediate EE",
			connectionType: obfuscated2.ConnectionTypeIntermediate,
			packet:         []byte{0x04, 0x00, 0x00, 0x00, 0xde, 0xad, 0xbe, 0xef},
		},
		{
			name:           "padded intermediate DD",
			connectionType: obfuscated2.ConnectionTypePaddedIntermediate,
			packet:         []byte{0x06, 0x00, 0x00, 0x00, 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			proxyConn, fakeDC := net.Pipe()
			defer proxyConn.Close()
			defer fakeDC.Close()
			if err := fakeDC.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatalf("set fake DC deadline: %v", err)
			}

			type result struct {
				encryptor cipher.Stream
				decryptor cipher.Stream
				err       error
			}
			resultCh := make(chan result, 1)
			go func() {
				encryptor, decryptor, err := writeDCHandshake(proxyConn, -3, tc.connectionType)
				resultCh <- result{encryptor: encryptor, decryptor: decryptor, err: err}
			}()

			wire := make([]byte, obfuscated2.FrameSize)
			if _, err := io.ReadFull(fakeDC, wire); err != nil {
				t.Fatalf("fake DC read handshake: %v", err)
			}
			gotType, gotDC, dcDecryptor, dcEncryptor := decodeFakeDCHandshake(t, wire)
			if gotType != tc.connectionType {
				t.Errorf("connection type = 0x%08x, want 0x%08x", gotType, tc.connectionType)
			}
			if gotDC != -3 {
				t.Errorf("DC ID = %d, want -3", gotDC)
			}

			gotResult := <-resultCh
			if gotResult.err != nil {
				t.Fatalf("writeDCHandshake: %v", gotResult.err)
			}

			toDC := make([]byte, len(tc.packet))
			gotResult.encryptor.XORKeyStream(toDC, tc.packet)
			gotAtDC := make([]byte, len(tc.packet))
			dcDecryptor.XORKeyStream(gotAtDC, toDC)
			if !bytes.Equal(gotAtDC, tc.packet) {
				t.Errorf("relayed packet at fake DC = %x, want unchanged %x", gotAtDC, tc.packet)
			}

			toProxy := make([]byte, len(tc.packet))
			dcEncryptor.XORKeyStream(toProxy, tc.packet)
			gotAtProxy := make([]byte, len(tc.packet))
			gotResult.decryptor.XORKeyStream(gotAtProxy, toProxy)
			if !bytes.Equal(gotAtProxy, tc.packet) {
				t.Errorf("fake DC response at proxy = %x, want unchanged %x", gotAtProxy, tc.packet)
			}
		})
	}
}

func TestWriteDCHandshake_RejectsUnsupportedPacketFraming(t *testing.T) {
	_, _, err := writeDCHandshake(io.Discard, 2, obfuscated2.ConnectionType(0xabababab))
	if err != obfuscated2.ErrUnsupportedConnection {
		t.Fatalf("error = %v, want %v", err, obfuscated2.ErrUnsupportedConnection)
	}
}

// TestBuildProxyProtocolV1_IPv4 tests building v1 header for IPv4.
func TestBuildProxyProtocolV1_IPv4(t *testing.T) {
	src := &net.TCPAddr{IP: net.ParseIP("192.168.1.100"), Port: 12345}
	dst := &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 443}

	header := buildProxyProtocolV1(src, dst)

	expected := "PROXY TCP4 192.168.1.100 10.0.0.1 12345 443\r\n"
	if string(header) != expected {
		t.Errorf("buildProxyProtocolV1 IPv4:\ngot:  %q\nwant: %q", string(header), expected)
	}
}

// TestBuildProxyProtocolV1_IPv6 tests building v1 header for IPv6.
func TestBuildProxyProtocolV1_IPv6(t *testing.T) {
	src := &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 54321}
	dst := &net.TCPAddr{IP: net.ParseIP("2001:db8::2"), Port: 443}

	header := buildProxyProtocolV1(src, dst)

	expected := "PROXY TCP6 2001:db8::1 2001:db8::2 54321 443\r\n"
	if string(header) != expected {
		t.Errorf("buildProxyProtocolV1 IPv6:\ngot:  %q\nwant: %q", string(header), expected)
	}
}

// TestBuildProxyProtocolV2_IPv4 tests building v2 binary header for IPv4.
func TestBuildProxyProtocolV2_IPv4(t *testing.T) {
	src := &net.TCPAddr{IP: net.ParseIP("192.168.1.100"), Port: 12345}
	dst := &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 443}

	header := buildProxyProtocolV2(src, dst)

	// Verify header structure
	if len(header) != 28 { // 16 bytes header + 12 bytes IPv4 addresses
		t.Errorf("IPv4 header length: got %d, want 28", len(header))
	}

	// Verify signature (first 12 bytes)
	if string(header[:12]) != string(proxyProtocolV2Sig) {
		t.Error("v2 signature mismatch")
	}

	// Verify version and command (byte 12)
	if header[12] != 0x21 { // version 2, PROXY command
		t.Errorf("ver_cmd: got 0x%02x, want 0x21", header[12])
	}

	// Verify family (byte 13)
	if header[13] != 0x11 { // AF_INET + STREAM
		t.Errorf("family: got 0x%02x, want 0x11", header[13])
	}

	// Verify address length (bytes 14-15)
	addrLen := int(header[14])<<8 | int(header[15])
	if addrLen != 12 {
		t.Errorf("addr_len: got %d, want 12", addrLen)
	}

	// Verify source IP (bytes 16-19)
	srcIP := net.IP(header[16:20])
	if !srcIP.Equal(net.ParseIP("192.168.1.100").To4()) {
		t.Errorf("srcIP: got %s, want 192.168.1.100", srcIP)
	}

	// Verify destination IP (bytes 20-23)
	dstIP := net.IP(header[20:24])
	if !dstIP.Equal(net.ParseIP("10.0.0.1").To4()) {
		t.Errorf("dstIP: got %s, want 10.0.0.1", dstIP)
	}

	// Verify source port (bytes 24-25)
	srcPort := int(header[24])<<8 | int(header[25])
	if srcPort != 12345 {
		t.Errorf("srcPort: got %d, want 12345", srcPort)
	}

	// Verify destination port (bytes 26-27)
	dstPort := int(header[26])<<8 | int(header[27])
	if dstPort != 443 {
		t.Errorf("dstPort: got %d, want 443", dstPort)
	}
}

// TestBuildProxyProtocolV2_IPv6 tests building v2 binary header for IPv6.
func TestBuildProxyProtocolV2_IPv6(t *testing.T) {
	src := &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 54321}
	dst := &net.TCPAddr{IP: net.ParseIP("2001:db8::2"), Port: 443}

	header := buildProxyProtocolV2(src, dst)

	// Verify header structure
	if len(header) != 52 { // 16 bytes header + 36 bytes IPv6 addresses
		t.Errorf("IPv6 header length: got %d, want 52", len(header))
	}

	// Verify family (byte 13)
	if header[13] != 0x21 { // AF_INET6 + STREAM
		t.Errorf("family: got 0x%02x, want 0x21", header[13])
	}

	// Verify address length (bytes 14-15)
	addrLen := int(header[14])<<8 | int(header[15])
	if addrLen != 36 {
		t.Errorf("addr_len: got %d, want 36", addrLen)
	}
}

// TestBuildProxyProtocolHeader_Version tests version selection.
func TestBuildProxyProtocolHeader_Version(t *testing.T) {
	src := &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 1234}
	dst := &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 443}

	// Version 1 should return text format
	v1 := buildProxyProtocolHeader(1, src, dst)
	if v1[0] != 'P' {
		t.Error("v1 should start with 'P'")
	}

	// Version 2 should return binary format
	v2 := buildProxyProtocolHeader(2, src, dst)
	if v2[0] != 0x0D {
		t.Error("v2 should start with 0x0D")
	}
}

// TestBuildProxyProtocolHeader_NonTCPAddr tests handling of non-TCP addresses.
func TestBuildProxyProtocolHeader_NonTCPAddr(t *testing.T) {
	// Using UDP address (shouldn't happen but test defensive code)
	src := &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 1234}
	dst := &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 443}

	header := buildProxyProtocolHeader(1, src, dst)
	if header != nil {
		t.Error("should return nil for non-TCP source address")
	}

	header = buildProxyProtocolHeader(1, dst, src)
	if header != nil {
		t.Error("should return nil for non-TCP destination address")
	}
}

// TestFilterAddrs_IPv4Only tests filtering to IPv4 addresses only.
func TestFilterAddrs_IPv4Only(t *testing.T) {
	addrs := []dc.Addr{
		{Network: "tcp4", Address: "1.1.1.1:443"},
		{Network: "tcp6", Address: "[2001:db8::1]:443"},
		{Network: "tcp4", Address: "2.2.2.2:443"},
		{Network: "tcp6", Address: "[2001:db8::2]:443"},
	}

	filtered := filterAddrs(addrs, false) // wantIPv6=false means IPv4

	if len(filtered) != 2 {
		t.Errorf("expected 2 IPv4 addresses, got %d", len(filtered))
	}

	for _, a := range filtered {
		if a.IsIPv6() {
			t.Errorf("unexpected IPv6 address: %s", a.Address)
		}
	}
}

// TestFilterAddrs_IPv6Only tests filtering to IPv6 addresses only.
func TestFilterAddrs_IPv6Only(t *testing.T) {
	addrs := []dc.Addr{
		{Network: "tcp4", Address: "1.1.1.1:443"},
		{Network: "tcp6", Address: "[2001:db8::1]:443"},
		{Network: "tcp4", Address: "2.2.2.2:443"},
		{Network: "tcp6", Address: "[2001:db8::2]:443"},
	}

	filtered := filterAddrs(addrs, true) // wantIPv6=true

	if len(filtered) != 2 {
		t.Errorf("expected 2 IPv6 addresses, got %d", len(filtered))
	}

	for _, a := range filtered {
		if !a.IsIPv6() {
			t.Errorf("unexpected IPv4 address: %s", a.Address)
		}
	}
}

// TestFilterAddrs_Empty tests filtering an empty list.
func TestFilterAddrs_Empty(t *testing.T) {
	filtered := filterAddrs([]dc.Addr{}, true)
	if len(filtered) != 0 {
		t.Errorf("expected empty result, got %d", len(filtered))
	}
}

// TestFilterAddrs_NoMatch tests filtering when no addresses match.
func TestFilterAddrs_NoMatch(t *testing.T) {
	addrs := []dc.Addr{
		{Network: "tcp4", Address: "1.1.1.1:443"},
		{Network: "tcp4", Address: "2.2.2.2:443"},
	}

	// Filter for IPv6 when all are IPv4
	filtered := filterAddrs(addrs, true)
	if len(filtered) != 0 {
		t.Errorf("expected no addresses, got %d", len(filtered))
	}
}

// TestSortAddrsByPreference_PreferIPv4 tests sorting with IPv4 preference.
func TestSortAddrsByPreference_PreferIPv4(t *testing.T) {
	addrs := []dc.Addr{
		{Network: "tcp6", Address: "[2001:db8::1]:443"},
		{Network: "tcp4", Address: "1.1.1.1:443"},
		{Network: "tcp6", Address: "[2001:db8::2]:443"},
		{Network: "tcp4", Address: "2.2.2.2:443"},
	}

	sorted := sortAddrsByPreference(addrs, false) // preferIPv6=false means prefer IPv4

	if len(sorted) != 4 {
		t.Fatalf("expected 4 addresses, got %d", len(sorted))
	}

	// First two should be IPv4
	if sorted[0].IsIPv6() || sorted[1].IsIPv6() {
		t.Error("IPv4 addresses should come first")
	}

	// Last two should be IPv6
	if !sorted[2].IsIPv6() || !sorted[3].IsIPv6() {
		t.Error("IPv6 addresses should come last")
	}

	// Verify relative order within each group is preserved
	if sorted[0].Address != "1.1.1.1:443" {
		t.Errorf("first IPv4 should be 1.1.1.1:443, got %s", sorted[0].Address)
	}
	if sorted[1].Address != "2.2.2.2:443" {
		t.Errorf("second IPv4 should be 2.2.2.2:443, got %s", sorted[1].Address)
	}
}

// TestSortAddrsByPreference_PreferIPv6 tests sorting with IPv6 preference.
func TestSortAddrsByPreference_PreferIPv6(t *testing.T) {
	addrs := []dc.Addr{
		{Network: "tcp4", Address: "1.1.1.1:443"},
		{Network: "tcp6", Address: "[2001:db8::1]:443"},
		{Network: "tcp4", Address: "2.2.2.2:443"},
		{Network: "tcp6", Address: "[2001:db8::2]:443"},
	}

	sorted := sortAddrsByPreference(addrs, true) // preferIPv6=true

	if len(sorted) != 4 {
		t.Fatalf("expected 4 addresses, got %d", len(sorted))
	}

	// First two should be IPv6
	if !sorted[0].IsIPv6() || !sorted[1].IsIPv6() {
		t.Error("IPv6 addresses should come first")
	}

	// Last two should be IPv4
	if sorted[2].IsIPv6() || sorted[3].IsIPv6() {
		t.Error("IPv4 addresses should come last")
	}
}

// TestSortAddrsByPreference_AllSameFamily tests sorting when all addresses are same family.
func TestSortAddrsByPreference_AllSameFamily(t *testing.T) {
	addrs := []dc.Addr{
		{Network: "tcp4", Address: "1.1.1.1:443"},
		{Network: "tcp4", Address: "2.2.2.2:443"},
		{Network: "tcp4", Address: "3.3.3.3:443"},
	}

	sorted := sortAddrsByPreference(addrs, true) // prefer IPv6, but all are IPv4

	if len(sorted) != 3 {
		t.Fatalf("expected 3 addresses, got %d", len(sorted))
	}

	// Order should be preserved
	for i, a := range sorted {
		if a.Address != addrs[i].Address {
			t.Errorf("order not preserved at index %d", i)
		}
	}
}

// TestSortAddrsByPreference_Empty tests sorting an empty list.
func TestSortAddrsByPreference_Empty(t *testing.T) {
	sorted := sortAddrsByPreference([]dc.Addr{}, true)
	if len(sorted) != 0 {
		t.Errorf("expected empty result, got %d", len(sorted))
	}
}

// TestGetFd_NonSyscallConn tests getFd with a connection that doesn't support SyscallConn.
func TestGetFd_NonSyscallConn(t *testing.T) {
	// net.Pipe() returns connections that don't support SyscallConn
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	fd := getFd(client)
	if fd != -1 {
		t.Errorf("getFd should return -1 for net.Pipe connection, got %d", fd)
	}
}

// BenchmarkBuildProxyProtocolV1 benchmarks v1 header building.
func BenchmarkBuildProxyProtocolV1(b *testing.B) {
	src := &net.TCPAddr{IP: net.ParseIP("192.168.1.100"), Port: 12345}
	dst := &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 443}

	b.ResetTimer()
	for b.Loop() {
		buildProxyProtocolV1(src, dst)
	}
}

// BenchmarkBuildProxyProtocolV2 benchmarks v2 header building.
func BenchmarkBuildProxyProtocolV2(b *testing.B) {
	src := &net.TCPAddr{IP: net.ParseIP("192.168.1.100"), Port: 12345}
	dst := &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 443}

	b.ResetTimer()
	for b.Loop() {
		buildProxyProtocolV2(src, dst)
	}
}

// BenchmarkFilterAddrs benchmarks address filtering.
func BenchmarkFilterAddrs(b *testing.B) {
	addrs := make([]dc.Addr, 10)
	for i := range addrs {
		if i%2 == 0 {
			addrs[i] = dc.Addr{Network: "tcp4", Address: "1.1.1.1:443"}
		} else {
			addrs[i] = dc.Addr{Network: "tcp6", Address: "[2001:db8::1]:443"}
		}
	}

	b.ResetTimer()
	for b.Loop() {
		filterAddrs(addrs, false)
	}
}

// BenchmarkSortAddrsByPreference benchmarks address sorting.
func BenchmarkSortAddrsByPreference(b *testing.B) {
	addrs := make([]dc.Addr, 10)
	for i := range addrs {
		if i%2 == 0 {
			addrs[i] = dc.Addr{Network: "tcp4", Address: "1.1.1.1:443"}
		} else {
			addrs[i] = dc.Addr{Network: "tcp6", Address: "[2001:db8::1]:443"}
		}
	}

	b.ResetTimer()
	for b.Loop() {
		sortAddrsByPreference(addrs, false)
	}
}
