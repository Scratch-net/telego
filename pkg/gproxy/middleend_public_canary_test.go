//go:build linux && me_pressure_investigation

package gproxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/panjf2000/gnet/v2"
	"github.com/pelletier/go-toml/v2"
	"github.com/scratch-net/telego/pkg/transport/middleend"
	"github.com/scratch-net/telego/pkg/transport/obfuscated2"
)

var publicCanaryConfigPath = flag.String("me-public-canary-config", "", "Read the local VPS config privately and run the public DD/EE protocol canary")

const publicCanaryDC = 2

// Wire facts are from Telegram's official authentication and serialization
// documentation, checked on 2026-09-15:
// https://core.telegram.org/mtproto/auth_key
// https://core.telegram.org/mtproto/samples-auth_key
// https://core.telegram.org/mtproto/description#message-identifier-msg-id
// https://core.telegram.org/mtproto/serialize
const publicCanaryResPQ uint32 = 0x05162463
const publicCanaryVector uint32 = 0x1cb5c415

type publicCanarySettings struct {
	address, hostname, metricsURL string
	secret                        []byte
}

func (publicCanarySettings) String() string     { return "publicCanarySettings{redacted}" }
func (s publicCanarySettings) GoString() string { return s.String() }

func loadPublicCanarySettings(path string) (publicCanarySettings, error) {
	var result publicCanarySettings
	file, err := os.Open(path)
	if err != nil {
		return result, errors.New("private configuration is unreadable")
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	if err != nil || len(data) > 1<<20 {
		return result, errors.New("private configuration read failed")
	}
	defer clear(data)
	// This test package cannot import pkg/config, which imports gproxy.
	// These fields follow Config and ToGProxyConfig in pkg/config/config.go.
	var config struct {
		BindTo  string            `toml:"bind-to"`
		Secrets map[string]string `toml:"secrets"`
		General struct {
			BindTo string `toml:"bind-to"`
		} `toml:"general"`
		TLS struct {
			MaskHost string `toml:"mask-host"`
		} `toml:"tls-fronting"`
		Metrics struct {
			BindTo string `toml:"bind-to"`
			Path   string `toml:"path"`
		} `toml:"metrics"`
		MiddleEnd struct {
			Enabled bool `toml:"enabled"`
		} `toml:"middle-end"`
	}
	if toml.Unmarshal(data, &config) != nil {
		return result, errors.New("private configuration parse failed")
	}
	if !config.MiddleEnd.Enabled || len(config.Secrets) == 0 || config.TLS.MaskHost == "" {
		return result, errors.New("configuration lacks the required ME route or authentication settings")
	}
	key := config.Secrets[slices.Sorted(maps.Keys(config.Secrets))[0]]
	result.secret, err = hex.DecodeString(strings.TrimSpace(key))
	if err != nil || len(result.secret) != 16 {
		clear(result.secret)
		return publicCanarySettings{}, errors.New("private secret format is invalid")
	}
	result.hostname = config.TLS.MaskHost
	bind := config.General.BindTo
	if bind == "" {
		bind = config.BindTo
	}
	result.address, err = publicCanaryLocalAddress(bind)
	if err != nil {
		clear(result.secret)
		return publicCanarySettings{}, err
	}
	metricsAddress, err := publicCanaryLocalAddress(config.Metrics.BindTo)
	if err != nil {
		clear(result.secret)
		return publicCanarySettings{}, errors.New("local route metrics endpoint is unavailable")
	}
	pathValue := config.Metrics.Path
	if pathValue == "" {
		pathValue = "/metrics"
	}
	if !strings.HasPrefix(pathValue, "/") || strings.ContainsAny(pathValue, "?#\r\n") {
		clear(result.secret)
		return publicCanarySettings{}, errors.New("local route metrics path is invalid")
	}
	result.metricsURL = (&url.URL{Scheme: "http", Host: metricsAddress, Path: pathValue}).String()
	return result, nil
}

func publicCanaryLocalAddress(bind string) (string, error) {
	host, port, err := net.SplitHostPort(strings.TrimPrefix(bind, "tcp://"))
	if err != nil {
		return "", errors.New("local listener address is invalid")
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 {
		return "", errors.New("local listener port is invalid")
	}
	switch host {
	case "", "0.0.0.0":
		host = "127.0.0.1"
	case "::":
		host = "::1"
	}
	if net.ParseIP(host) == nil {
		return "", errors.New("canary requires a literal listener address")
	}
	return net.JoinHostPort(host, port), nil
}

func publicCanaryRequest(nonce [16]byte, messageID uint64) []byte {
	packet := make([]byte, middleend.UnencryptedMessageHeaderSize+20)
	binary.LittleEndian.PutUint64(packet[8:], messageID)
	binary.LittleEndian.PutUint32(packet[16:], 20)
	binary.LittleEndian.PutUint32(packet[20:], middleend.MTProtoReqPQMultiConstructor)
	copy(packet[24:], nonce[:])
	return packet
}

func publicCanaryMessageID(now time.Time, previous uint64) uint64 {
	fraction := (uint64(now.Nanosecond()) << 32) / 1_000_000_000
	id := (uint64(now.Unix())<<32 | fraction) &^ 3
	if id <= previous {
		id = previous + 4
	}
	if uint32(id) == 0 {
		id += 4
	}
	return id
}

func TestPublicCanaryOfficialWireAndRouteFixtures(t *testing.T) {
	requestHex := "000000000000000078f404006170466a14000000f18e7ebe51a1143fc7a3666be4be54d6890a02dc"
	responseHex := "000000000000000001f4ccc26170466a500000006324160551a1143fc7a3666be4be54d6890a02dc63248f6748214eab8a2f4cc876e11974082e9cdb98c80cda4b00000015c4b51c0300000085fd64de851d9dd0a5b7f709355fc30b216be86c022bb4c3"
	request, _ := hex.DecodeString(requestHex)
	response, _ := hex.DecodeString(responseHex)
	var nonce [16]byte
	copy(nonce[:], request[24:])
	if !bytes.Equal(publicCanaryRequest(nonce, binary.LittleEndian.Uint64(request[8:])), request) {
		t.Fatal("req_pq_multi differs from the official wire sample")
	}
	if err := validatePublicCanaryResPQ(response, nonce); err != nil {
		t.Fatalf("official resPQ sample: %v", err)
	}
	for _, offset := range []int{0, 8, 16, 20, 24, 65, 68, 72} {
		bad := bytes.Clone(response)
		bad[offset] ^= 1
		if validatePublicCanaryResPQ(bad, nonce) == nil {
			t.Fatalf("changed response accepted at offset %d", offset)
		}
	}
	for size := range len(response) {
		if validatePublicCanaryResPQ(response[:size], nonce) == nil {
			t.Fatalf("truncated response accepted at length %d", size)
		}
	}
	now := time.Unix(1_700_000_000, 123_456_789)
	id := publicCanaryMessageID(now, 0)
	if id&3 != 0 || uint32(id) == 0 || id>>32 != uint64(now.Unix()) || publicCanaryMessageID(now, id) != id+4 {
		t.Fatal("client message identifiers lost timestamp, fraction, or monotonicity")
	}
	before := publicCanaryRoutes{commits: 5, fallback: 2, ready: true, admitting: true}
	after := before
	after.commits++
	if validatePublicCanaryRouteChange(before, after) != nil {
		t.Fatal("valid route delta rejected")
	}
	after.fallback++
	if validatePublicCanaryRouteChange(before, after) == nil || validatePublicCanaryRouteChange(before, before) == nil {
		t.Fatal("fallback or missing ME commit accepted as route proof")
	}
}

func TestPublicCanaryDDAndEEPauseFixture(t *testing.T) {
	handler, link, _, _, _, _ := newMiddleEndTestHandler(t, publicCanaryDC, obfuscated2.ConnectionTypeIntermediate, nil)
	engine, err := gnet.NewClient(handler)
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = engine.Stop() })
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	var workers sync.WaitGroup
	failures := make(chan error, 4)
	workers.Go(func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				if ctx.Err() == nil {
					failures <- errors.New("fixture listener failed")
				}
				return
			}
			if _, err := engine.Enroll(conn); err != nil {
				_ = conn.Close()
				failures <- errors.New("fixture enrollment failed")
				return
			}
		}
	})
	workers.Go(func() {
		for {
			select {
			case <-ctx.Done():
				return
			case submission := <-link.submitted:
				if len(submission.Payload) < 4 || binary.LittleEndian.Uint32(submission.Payload) != middleend.OperationProxyRequest {
					continue
				}
				request, err := middleend.ParseProxyRequest(submission.Payload)
				if err != nil || len(request.Packet) != 40 || binary.LittleEndian.Uint64(request.Packet) != 0 ||
					binary.LittleEndian.Uint32(request.Packet[20:]) != middleend.MTProtoReqPQMultiConstructor {
					failures <- errors.New("fixture received invalid req_pq_multi")
					return
				}
				response := make([]byte, 84)
				binary.LittleEndian.PutUint64(response[8:], binary.LittleEndian.Uint64(request.Packet[8:])|1)
				binary.LittleEndian.PutUint32(response[16:], uint32(len(response)-20))
				binary.LittleEndian.PutUint32(response[20:], publicCanaryResPQ)
				copy(response[24:40], request.Packet[24:40])
				response[56] = 8
				copy(response[57:65], []byte{0x2e, 0x9c, 0xdb, 0x98, 0xc8, 0x0c, 0xda, 0x4b})
				binary.LittleEndian.PutUint32(response[68:], publicCanaryVector)
				binary.LittleEndian.PutUint32(response[72:], 1)
				binary.LittleEndian.PutUint64(response[76:], 1)
				link.emit(middleend.LinkEvent{Kind: middleend.LinkEventProxyAnswer, ConnectionID: request.ConnectionID, Packet: response})
			}
		}
	})
	t.Cleanup(func() {
		cancel()
		_ = listener.Close()
		workers.Wait()
		close(failures)
		for err := range failures {
			t.Error(err)
		}
	})
	metrics := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		stats := handler.middleEnd.stats()
		fmt.Fprintf(w, "telego_middleend_frontend_route_commits_total{route=\"middleend\"} %d\n"+
			"telego_middleend_frontend_route_commits_total{route=\"direct_fallback\"} %d\n"+
			"telego_middleend_links{dc=\"2\",role=\"active\",state=\"ready\"} 1\n"+
			"telego_middleend_admitting 1\n", stats.MiddleEndBindingsTotal, stats.DirectFallbacksTotal)
	}))
	defer metrics.Close()
	settings := publicCanarySettings{address: listener.Addr().String(), hostname: "example.com", metricsURL: metrics.URL, secret: []byte("0123456789abcdef")}
	for _, tls := range []bool{false, true} {
		protocolContext, stop := context.WithTimeout(t.Context(), 5*time.Second)
		_, err := runPublicCanaryProtocol(t, protocolContext, settings, tls, 5*time.Millisecond)
		stop()
		if err != nil {
			t.Fatal(err)
		}
	}
}

func validatePublicCanaryResPQ(packet []byte, nonce [16]byte) error {
	if len(packet) < 64 || len(packet) > 4096 || binary.LittleEndian.Uint64(packet) != 0 ||
		binary.LittleEndian.Uint64(packet[8:])&3 != 1 ||
		int(binary.LittleEndian.Uint32(packet[16:])) != len(packet)-middleend.UnencryptedMessageHeaderSize {
		return errors.New("invalid unencrypted response envelope")
	}
	if binary.LittleEndian.Uint32(packet[20:]) != publicCanaryResPQ || !bytes.Equal(packet[24:40], nonce[:]) {
		return errors.New("response constructor or ordered nonce differs")
	}
	// The remaining fields must form a complete bounded TL resPQ object.
	rest := packet[56:] // after constructor, nonce, and server_nonce
	length, prefix := int(rest[0]), 1
	if length == 254 {
		if len(rest) < 4 {
			return errors.New("truncated PQ string")
		}
		length, prefix = int(rest[1])|int(rest[2])<<8|int(rest[3])<<16, 4
	}
	if length < 1 || length > 256 || prefix == 1 && length == 255 || prefix == 4 && length < 254 {
		return errors.New("invalid PQ string length")
	}
	stringBytes := (prefix + length + 3) &^ 3
	if len(rest) < stringBytes+8 || binary.LittleEndian.Uint32(rest[stringBytes:]) != publicCanaryVector {
		return errors.New("invalid server fingerprint vector")
	}
	for _, padding := range rest[prefix+length : stringBytes] {
		if padding != 0 {
			return errors.New("invalid PQ string padding")
		}
	}
	count := binary.LittleEndian.Uint32(rest[stringBytes+4:])
	if count == 0 || count > 64 || len(rest) != stringBytes+8+int(count)*8 {
		return errors.New("invalid server fingerprint count")
	}
	return nil
}

func TestPublicCanaryPrivateConfiguration(t *testing.T) {
	const key = "30313233343536373839616263646566"
	text := "bind-to = \"0.0.0.0:1234\"\n[general]\nbind-to = \"0.0.0.0:4321\"\n" +
		"[secrets]\nmain = \"" + key + "\"\n[tls-fronting]\nmask-host = \"example.com\"\n" +
		"[metrics]\nbind-to = \"127.0.0.1:9999\"\n[middle-end]\nenabled = true\n"
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	settings, err := loadPublicCanarySettings(path)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(settings.secret)
	if settings.address != "127.0.0.1:4321" || settings.metricsURL != "http://127.0.0.1:9999/metrics" ||
		settings.hostname != "example.com" || string(settings.secret) != "0123456789abcdef" {
		t.Fatal("private configuration differs from production field precedence")
	}
	if fmt.Sprintf("%#v", settings) != "publicCanarySettings{redacted}" {
		t.Fatal("private settings formatting exposes configuration")
	}
	badKey := "private-invalid-key"
	if err := os.WriteFile(path, []byte(strings.Replace(text, key, badKey, 1)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadPublicCanarySettings(path); err == nil || strings.Contains(err.Error(), badKey) {
		t.Fatal("invalid private configuration passed or exposed its value")
	}
	if _, err := parsePublicCanaryRoutes([]byte("telego_middleend_admitting 1\n")); err == nil {
		t.Fatal("missing route evidence accepted")
	}
}

type publicCanaryRoutes struct {
	commits, fallback float64
	ready, admitting  bool
}

func parsePublicCanaryRoutes(data []byte) (publicCanaryRoutes, error) {
	var result publicCanaryRoutes
	var commitsFound, fallbackFound, readyFound, admittingFound bool
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), 64<<10)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		name, _, _ := strings.Cut(fields[0], "{")
		if name != "telego_middleend_frontend_route_commits_total" && name != "telego_middleend_links" && name != "telego_middleend_admitting" {
			continue
		}
		value, err := strconv.ParseFloat(fields[1], 64)
		if err != nil || math.IsNaN(value) || math.IsInf(value, 0) || value < 0 {
			return result, errors.New("route metric value is invalid")
		}
		switch name {
		case "telego_middleend_frontend_route_commits_total":
			if strings.Contains(fields[0], `route="middleend"`) {
				result.commits, commitsFound = value, true
			} else if strings.Contains(fields[0], `route="direct_fallback"`) {
				result.fallback, fallbackFound = value, true
			}
		case "telego_middleend_links":
			if strings.Contains(fields[0], `role="active"`) && strings.Contains(fields[0], `dc="2"`) && strings.Contains(fields[0], `state="ready"`) {
				result.ready, readyFound = value > 0, true
			}
		case "telego_middleend_admitting":
			result.admitting, admittingFound = value == 1, true
		}
	}
	if scanner.Err() != nil || !commitsFound || !fallbackFound || !readyFound || !admittingFound {
		return result, errors.New("required ME route metrics are missing")
	}
	return result, nil
}

func fetchPublicCanaryRoutes(ctx context.Context, endpoint string) (publicCanaryRoutes, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return publicCanaryRoutes{}, errors.New("route metrics request is invalid")
	}
	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{Proxy: nil},
		CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect rejected") }}
	defer client.CloseIdleConnections()
	response, err := client.Do(request)
	if err != nil {
		return publicCanaryRoutes{}, errors.New("route metrics request failed")
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, (4<<20)+1))
	if err != nil || len(data) > 4<<20 || response.StatusCode != http.StatusOK {
		return publicCanaryRoutes{}, errors.New("route metrics response failed")
	}
	return parsePublicCanaryRoutes(data)
}

func validatePublicCanaryRouteChange(before, after publicCanaryRoutes) error {
	if !before.ready || !before.admitting || !after.ready || !after.admitting ||
		after.commits < before.commits+1 || after.fallback != before.fallback {
		return errors.New("ME route evidence is inconclusive")
	}
	return nil
}

func runPublicCanaryProtocol(t *testing.T, ctx context.Context, settings publicCanarySettings, tls bool, pause time.Duration) (time.Duration, error) {
	before, err := fetchPublicCanaryRoutes(ctx, settings.metricsURL)
	if err != nil {
		return 0, err
	}
	if !before.ready || !before.admitting {
		return 0, errors.New("ME route is not ready")
	}
	client, err := pressureDialNativeWithSecret(t, ctx, settings.address, publicCanaryDC, tls, settings.secret, settings.hostname)
	if err != nil {
		return 0, errors.New("public protocol handshake failed")
	}
	defer client.close()
	started := time.Now()
	var previous uint64
	for sequence := range 3 {
		var nonce [16]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return 0, errors.New("request nonce generation failed")
		}
		previous = publicCanaryMessageID(time.Now(), previous)
		if err := client.sendPacket(publicCanaryRequest(nonce, previous)); err != nil {
			return 0, errors.New("public protocol request failed")
		}
		if sequence == 1 {
			select {
			case <-time.After(pause):
			case <-ctx.Done():
				return 0, errors.New("read pause deadline expired")
			}
		}
		packet, err := client.readPacket()
		if err != nil {
			return 0, errors.New("public protocol response failed")
		}
		err = validatePublicCanaryResPQ(packet, nonce)
		clear(packet)
		if err != nil {
			return 0, err
		}
	}
	after, err := fetchPublicCanaryRoutes(ctx, settings.metricsURL)
	if err != nil {
		return 0, err
	}
	if err := validatePublicCanaryRouteChange(before, after); err != nil {
		return 0, err
	}
	return time.Since(started), nil
}

func TestMiddleEndPublicCanary(t *testing.T) {
	if *publicCanaryConfigPath == "" {
		t.Skip("public canary requires a private local configuration path")
	}
	settings, err := loadPublicCanarySettings(*publicCanaryConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(settings.secret)
	// Give deterministic fixture handshakes a fresh replay identity per run.
	var serial [8]byte
	if _, err := rand.Read(serial[:]); err != nil {
		t.Fatal("canary replay identity generation failed")
	}
	pressureClientSerial.Store(binary.LittleEndian.Uint64(serial[:]))
	for _, tls := range []bool{false, true} {
		mode := map[bool]string{false: "dd", true: "ee"}[tls]
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()
			elapsed, err := runPublicCanaryProtocol(t, ctx, settings, tls, 250*time.Millisecond)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("protocol=%s responses=3 pause_ms=250 ordered=true me_route=true elapsed_ms=%d", mode, elapsed.Milliseconds())
		})
	}
}
