package webproxy

import (
	"bytes"
	"encoding/binary"
	"io"
	"net/http"
	"strconv"
	"testing"
	"time"
)

func newStreamDownApplication(t *testing.T, longPoll time.Duration, enabled bool, batch int) (*httpTestApplication, CreateResult) {
	t.Helper()
	app := newHTTPTestApplicationWithConfig(t, longPoll, func(config *ManagerConfig) {
		config.StreamDownload = enabled
		if batch != 0 {
			config.Limits.CarrierBatchBytes = batch
		}
	}, nil)
	created := createTestSession(t, app.manager, app.profiles[0])
	if _, err := created.Session.ProcessUp(1, testFrameBatch(t, Frame{Type: FrameOpen, StreamID: 1})); err != nil {
		t.Fatal(err)
	}
	return app, created
}

func streamDownRequest(t *testing.T, app *httpTestApplication, client *http.Client, token string, cursor uint64, stream bool) *http.Response {
	t.Helper()
	headers := map[string]string{"Authorization": "Bearer " + token, "X-Down-Cursor": strconv.FormatUint(cursor, 10)}
	if stream {
		headers["Accept"] = downStreamMediaType
	}
	return app.do(t, client, "POST", "/api/v1/down", nil, headers)
}

func echoData(t *testing.T, session *Session, sequence uint64, payload string) {
	t.Helper()
	if _, err := session.ProcessUp(sequence, testFrameBatch(t, Frame{Type: FrameData, StreamID: 1, Payload: []byte(payload)})); err != nil {
		t.Fatal(err)
	}
}

// readDataFrame returns the next DATA payload and skips WINDOW credit frames.
func readDataFrame(t *testing.T, body io.Reader) string {
	t.Helper()
	for {
		header := make([]byte, FrameHeaderSize)
		if _, err := io.ReadFull(body, header); err != nil {
			t.Fatalf("read frame header: %v", err)
		}
		payload := make([]byte, binary.BigEndian.Uint32(header[4:]))
		if _, err := io.ReadFull(body, payload); err != nil {
			t.Fatalf("read frame payload: %v", err)
		}
		switch FrameType(header[0]) {
		case FrameData:
			return string(payload)
		case FrameWindow:
		default:
			t.Fatalf("frame type = %#x", header[0])
		}
	}
}

func dataPayloads(t *testing.T, body []byte) string {
	t.Helper()
	if len(body) == 0 {
		return ""
	}
	frames, err := ParseBatch(body)
	if err != nil {
		t.Fatal(err)
	}
	var result string
	for _, frame := range frames {
		if frame.Type == FrameData {
			result += string(frame.Payload)
		}
	}
	return result
}

func TestStreamDownloadAppendsFramesToOpenResponse(t *testing.T) {
	const longPoll = 400 * time.Millisecond
	app, created := newStreamDownApplication(t, longPoll, true, 0)
	client := &http.Client{Timeout: 5 * time.Second}
	echoData(t, created.Session, 2, "first")
	response := streamDownRequest(t, app, client, created.Token, 0, true)
	defer response.Body.Close()
	if response.StatusCode != 200 || len(response.TransferEncoding) != 1 || response.TransferEncoding[0] != "chunked" ||
		response.Header.Get("X-Down-Cursor") != "1" || response.Header.Get("X-Accel-Buffering") != "no" {
		t.Fatalf("stream response = %d %v %#v", response.StatusCode, response.TransferEncoding, response.Header)
	}
	if got := readDataFrame(t, response.Body); got != "first" {
		t.Fatalf("first frame = %q", got)
	}
	started := time.Now()
	echoData(t, created.Session, 3, "second")
	if got := readDataFrame(t, response.Body); got != "second" {
		t.Fatalf("appended frame = %q", got)
	}
	if elapsed := time.Since(started); elapsed >= longPoll/2 {
		t.Fatalf("appended frame waited %v", elapsed)
	}
	rest, err := io.ReadAll(response.Body)
	if err != nil || len(rest) != 0 {
		t.Fatalf("stream end = %x, %v", rest, err)
	}
	// The next poll acknowledges the whole streamed batch.
	next := streamDownRequest(t, app, client, created.Token, 1, false)
	body := readHTTPBody(t, next)
	if next.StatusCode != 204 || len(body) != 0 || next.Header.Get("X-Down-Cursor") != "1" {
		t.Fatalf("acknowledging poll = %d %#v %x", next.StatusCode, next.Header, body)
	}
	created.Session.mu.Lock()
	unacked := len(created.Session.carrierLanes[0].unacked)
	created.Session.mu.Unlock()
	if unacked != 0 {
		t.Fatalf("acknowledged stream retained %d bytes", unacked)
	}
}

func TestStreamDownloadReplaysBatchAfterBrokenStream(t *testing.T) {
	app, created := newStreamDownApplication(t, 2*time.Second, true, 0)
	echoData(t, created.Session, 2, "first")
	streamClient := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
	response := streamDownRequest(t, app, streamClient, created.Token, 0, true)
	if got := readDataFrame(t, response.Body); got != "first" {
		t.Fatalf("first frame = %q", got)
	}
	echoData(t, created.Session, 3, "second")
	_ = response.Body.Close()
	streamClient.CloseIdleConnections()
	echoData(t, created.Session, 4, "third")

	client := &http.Client{Timeout: 5 * time.Second}
	replay := streamDownRequest(t, app, client, created.Token, 0, false)
	replayBody := readHTTPBody(t, replay)
	if replay.StatusCode != 200 || replay.Header.Get("X-Down-Cursor") != "1" || replay.ContentLength != int64(len(replayBody)) {
		t.Fatalf("replay = %d %#v length %d", replay.StatusCode, replay.Header, replay.ContentLength)
	}
	received := dataPayloads(t, replayBody)
	if received != "first" && received != "firstsecond" && received != "firstsecondthird" {
		t.Fatalf("replay payloads = %q", received)
	}
	for cursor := uint64(1); received != "firstsecondthird"; cursor++ {
		if cursor > 3 {
			t.Fatalf("downlink payloads = %q", received)
		}
		next := streamDownRequest(t, app, client, created.Token, cursor, false)
		received += dataPayloads(t, readHTTPBody(t, next))
	}
	created.Session.Close()
	eventually(t, 2*time.Second, func() bool {
		capacity := app.manager.Capacity()
		return capacity.PendingBytes == 0 && capacity.PendingItems == 0
	})
}

func TestStreamDownloadEndsWhenSupersededAndNewPollReplays(t *testing.T) {
	app, created := newStreamDownApplication(t, 3*time.Second, true, 0)
	echoData(t, created.Session, 2, "first")
	streamClient := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{}}
	response := streamDownRequest(t, app, streamClient, created.Token, 0, true)
	defer response.Body.Close()
	if got := readDataFrame(t, response.Body); got != "first" {
		t.Fatalf("first frame = %q", got)
	}
	ended := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, response.Body)
		close(ended)
	}()
	started := time.Now()
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{}}
	replay := streamDownRequest(t, app, client, created.Token, 0, false)
	replayBody := readHTTPBody(t, replay)
	if replay.StatusCode != 200 || dataPayloads(t, replayBody) != "first" {
		t.Fatalf("superseding poll = %d %x", replay.StatusCode, replayBody)
	}
	select {
	case <-ended:
	case <-time.After(2 * time.Second):
		t.Fatal("superseded stream stayed open")
	}
	if elapsed := time.Since(started); elapsed >= 2*time.Second {
		t.Fatalf("superseding poll waited %v", elapsed)
	}
}

func TestStreamDownloadEndsWhenBatchIsFull(t *testing.T) {
	const batch = 64
	app, created := newStreamDownApplication(t, 5*time.Second, true, batch)
	echoData(t, created.Session, 2, "a")
	client := &http.Client{Timeout: 5 * time.Second}
	response := streamDownRequest(t, app, client, created.Token, 0, true)
	defer response.Body.Close()
	if got := readDataFrame(t, response.Body); got != "a" {
		t.Fatalf("first frame = %q", got)
	}
	// This frame cannot fit after the first one, so the stream ends now.
	large := string(bytes.Repeat([]byte{'b'}, batch-FrameHeaderSize))
	started := time.Now()
	echoData(t, created.Session, 3, large)
	rest, err := io.ReadAll(response.Body)
	if err != nil || time.Since(started) > 2*time.Second || FrameHeaderSize+1+len(rest) > batch {
		t.Fatalf("full stream end = %d bytes, %v after %v", len(rest), err, time.Since(started))
	}
	received := dataPayloads(t, rest)
	for cursor := uint64(1); received != large; cursor++ {
		if cursor > 3 {
			t.Fatalf("later payloads = %q", received)
		}
		next := streamDownRequest(t, app, client, created.Token, cursor, false)
		received += dataPayloads(t, readHTTPBody(t, next))
	}
}

func TestStreamDownloadRequiresOptionAndHeader(t *testing.T) {
	for _, test := range []struct {
		name            string
		enabled, accept bool
	}{
		{"option off", false, true},
		{"header absent", true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			app, created := newStreamDownApplication(t, 300*time.Millisecond, test.enabled, 0)
			echoData(t, created.Session, 2, "plain")
			client := &http.Client{Timeout: 5 * time.Second}
			received := ""
			for cursor := uint64(0); received != "plain"; cursor++ {
				if cursor > 3 {
					t.Fatalf("payloads = %q", received)
				}
				response := streamDownRequest(t, app, client, created.Token, cursor, test.accept)
				body := readHTTPBody(t, response)
				if response.StatusCode != 200 || len(response.TransferEncoding) != 0 || response.ContentLength != int64(len(body)) {
					t.Fatalf("plain response = %d %v %d %x", response.StatusCode, response.TransferEncoding, response.ContentLength, body)
				}
				received += dataPayloads(t, body)
			}
		})
	}
}

func TestChunkedParts(t *testing.T) {
	if got := bytes.Join(chunkedParts(bytes.Repeat([]byte{'x'}, 26)), nil); string(got) != "1a\r\n"+string(bytes.Repeat([]byte{'x'}, 26))+"\r\n" {
		t.Fatalf("chunk = %q", got)
	}
}
