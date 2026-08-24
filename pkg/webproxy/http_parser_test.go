package webproxy

import (
	"errors"
	"strings"
	"testing"
)

func TestParseCarrierRequestHeaderSplitAndCanonicalValues(t *testing.T) {
	raw := "POST /api/v1/up HTTP/1.1\r\n" +
		"Host: proxy.example.com:443\r\n" +
		"Authorization: Bearer AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n" +
		"Content-Type: application/octet-stream\r\n" +
		"Content-Length: 8\r\n" +
		"X-Up-Seq: 1\r\n\r\n12345678"
	headerEnd := strings.Index(raw, "\r\n\r\n") + 4
	for split := 0; split < headerEnd; split++ {
		_, _, err := parseCarrierRequestHeader([]byte(raw[:split]))
		if !errors.Is(err, errHTTPIncomplete) {
			t.Fatalf("split %d error = %v, want incomplete", split, err)
		}
	}
	request, consumed, err := parseCarrierRequestHeader([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if consumed != headerEnd || request.method != "POST" || request.path != "/api/v1/up" ||
		request.query != "" || request.contentLength != 8 || !request.hasContentLength || request.close {
		t.Fatalf("parsed request = %#v, consumed %d", request, consumed)
	}
	if request.headers["x-up-seq"] != "1" || request.headers["host"] != "proxy.example.com:443" {
		t.Fatalf("parsed headers = %#v", request.headers)
	}
}

func TestParseCarrierRequestHeaderLimitsAndSmugglingRejection(t *testing.T) {
	validPrefix := "POST /api/v1/up HTTP/1.1\r\nHost: proxy.example.com\r\n"
	tests := map[string]string{
		"http 1.0":          "GET / HTTP/1.0\r\nHost: proxy.example.com\r\n\r\n",
		"absolute target":   "GET https://proxy.example.com/ HTTP/1.1\r\nHost: proxy.example.com\r\n\r\n",
		"missing host":      "GET / HTTP/1.1\r\nUser-Agent: x\r\n\r\n",
		"duplicate host":    "GET / HTTP/1.1\r\nHost: proxy.example.com\r\nHost: proxy.example.com\r\n\r\n",
		"folded header":     "GET / HTTP/1.1\r\nHost: proxy.example.com\r\n folded\r\n\r\n",
		"transfer encoding": validPrefix + "Transfer-Encoding: chunked\r\n\r\n",
		"te header":         validPrefix + "TE: trailers\r\nContent-Length: 0\r\n\r\n",
		"trailer header":    validPrefix + "Trailer: X-Checksum\r\nContent-Length: 0\r\n\r\n",
		"te and length":     validPrefix + "Transfer-Encoding: chunked\r\nContent-Length: 0\r\n\r\n",
		"duplicate length":  validPrefix + "Content-Length: 0\r\nContent-Length: 0\r\n\r\n",
		"leading zero":      validPrefix + "Content-Length: 01\r\n\r\n",
		"signed length":     validPrefix + "Content-Length: +1\r\n\r\n",
		"over uint64":       validPrefix + "Content-Length: 18446744073709551616\r\n\r\n",
		"expect continue":   validPrefix + "Expect: 100-continue\r\nContent-Length: 0\r\n\r\n",
		"bare newline":      "GET / HTTP/1.1\nHost: proxy.example.com\n\n",
		"bare return":       "GET / HTTP/1.1\rX-Header: bad",
	}
	upgrade, _, err := parseCarrierRequestHeader([]byte("GET /socket HTTP/1.1\r\nHost: proxy.example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"))
	if err != nil || !upgrade.upgrade || upgrade.close {
		t.Fatalf("ordinary upgrade = %#v, %v", upgrade, err)
	}
	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			if _, _, err := parseCarrierRequestHeader([]byte(raw)); !errors.Is(err, errHTTPMalformed) {
				t.Fatalf("error = %v, want malformed", err)
			}
		})
	}

	overHeader := "GET / HTTP/1.1\r\nHost: proxy.example.com\r\nX-Fill: " +
		strings.Repeat("a", maxHTTPHeaderBytes) + "\r\n\r\n"
	if _, _, err := parseCarrierRequestHeader([]byte(overHeader)); !errors.Is(err, errHTTPMalformed) {
		t.Fatalf("oversized header error = %v", err)
	}
	large, _, err := parseCarrierRequestHeader([]byte(validPrefix + "Content-Length: 2097153\r\n\r\n"))
	if err != nil || large.contentLength != maxCarrierBatchBytes+1 {
		t.Fatalf("ordinary large Content-Length = %d, %v", large.contentLength, err)
	}
}

func TestCanonicalDecimalAndBearerToken(t *testing.T) {
	for _, value := range []string{"0", "1", "18446744073709551615"} {
		if _, ok := canonicalDecimal(value); !ok {
			t.Errorf("canonicalDecimal(%q) rejected", value)
		}
	}
	for _, value := range []string{"", "00", "01", "+1", "-1", " 1", "1 ", "18446744073709551616"} {
		if _, ok := canonicalDecimal(value); ok {
			t.Errorf("canonicalDecimal(%q) accepted", value)
		}
	}
	token, _, err := newToken()
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := bearerToken("Bearer " + token); !ok || got != token {
		t.Fatalf("bearerToken rejected canonical token: %q, %v", got, ok)
	}
	for _, value := range []string{"", token, "bearer " + token, "Bearer  " + token, "Bearer " + token + " ", "Bearer invalid"} {
		if _, ok := bearerToken(value); ok {
			t.Errorf("bearerToken(%q) accepted", value)
		}
	}
}
