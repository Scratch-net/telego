package webproxy

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"
)

// A buffered reverse proxy sends the complete request body after the header.
// An early fallback or rejection must read that body before it closes. A
// close with unread input resets the connection, and Nginx then reports 502.
func TestHTTPEarlyResponseDrainsPendingBody(t *testing.T) {
	const size = 1 << 20
	for _, test := range []struct {
		name   string
		header func(token string) string
		status int
	}{
		{
			name: "ordinary site 418",
			header: func(string) string {
				return fmt.Sprintf("POST /upload HTTP/1.1\r\nHost: proxy.example.com\r\nContent-Type: application/octet-stream\r\nContent-Length: %d\r\n\r\n", size)
			},
			status: defaultPassthroughStatus,
		},
		{
			name: "unauthenticated carrier 419",
			header: func(string) string {
				return fmt.Sprintf("POST /api/v1/up HTTP/1.1\r\nHost: proxy.example.com\r\nAuthorization: Bearer invalid\r\nContent-Type: application/octet-stream\r\nContent-Length: %d\r\nX-Up-Seq: 1\r\n\r\n", size)
			},
			status: defaultSanitizedFallbackStatus,
		},
		{
			name: "uplink outside the sequence window 400",
			header: func(token string) string {
				return fmt.Sprintf("POST /api/v1/up HTTP/1.1\r\nHost: proxy.example.com\r\nAuthorization: Bearer %s\r\nContent-Type: application/octet-stream\r\nContent-Length: %d\r\nX-Up-Seq: %d\r\n\r\n", token, size, httpUpWindow+1)
			},
			status: http.StatusBadRequest,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			app := newHTTPTestApplicationWithConfig(t, time.Second, nil, func(config *HTTPServerConfig) {
				config.BodyTimeout = 5 * time.Second
				config.WriteTimeout = 5 * time.Second
			})
			created := createTestSession(t, app.manager, app.profiles[0])
			connection := dialHTTPTest(t, app.address)
			defer connection.Close()
			if err := connection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, err := io.WriteString(connection, test.header(created.Token)); err != nil {
				t.Fatal(err)
			}
			reader := bufio.NewReader(connection)
			response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodPost})
			if err != nil {
				t.Fatal(err)
			}
			_ = readHTTPBody(t, response)
			if response.StatusCode != test.status {
				t.Fatalf("status = %d, want %d", response.StatusCode, test.status)
			}
			if _, err := io.Copy(connection, bytes.NewReader(bytes.Repeat([]byte{0x5a}, size))); err != nil {
				t.Fatalf("early response reset the pending body: %v", err)
			}
			if _, err := reader.ReadByte(); err != io.EOF {
				t.Fatalf("drained body did not end with a clean close: %v", err)
			}
		})
	}
}
