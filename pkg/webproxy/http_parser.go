package webproxy

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const (
	maxHTTPHeaderBytes = 16 * 1024
	maxHTTPHeaders     = 100
	maxPipelineBytes   = 16 * 1024
	maxCreateBodyBytes = 64
)

var (
	errHTTPIncomplete = errors.New("incomplete HTTP request")
	errHTTPMalformed  = errors.New("malformed HTTP request")
)

type carrierRequest struct {
	method           string
	path             string
	query            string
	headers          map[string]string
	contentLength    uint64
	hasContentLength bool
	close            bool
	upgrade          bool
}

func parseCarrierRequestHeader(data []byte) (carrierRequest, int, error) {
	var request carrierRequest
	end := bytes.Index(data, []byte("\r\n\r\n"))
	if end < 0 {
		for index, value := range data {
			if value == '\n' && (index == 0 || data[index-1] != '\r') ||
				value == '\r' && index+1 < len(data) && data[index+1] != '\n' ||
				value == 0 || value == 0x7f ||
				(value < 0x20 && value != '\r' && value != '\t' && value != '\n') {
				return request, 0, fmt.Errorf("%w: invalid control byte", errHTTPMalformed)
			}
		}
		if len(data) >= maxHTTPHeaderBytes {
			return request, 0, fmt.Errorf("%w: header exceeds %d bytes", errHTTPMalformed, maxHTTPHeaderBytes)
		}
		return request, 0, errHTTPIncomplete
	}
	headerBytes := end + 4
	if headerBytes > maxHTTPHeaderBytes {
		return request, 0, fmt.Errorf("%w: header exceeds %d bytes", errHTTPMalformed, maxHTTPHeaderBytes)
	}
	for index, value := range data[:end] {
		bareReturn := value == '\r' && (index+1 >= end || data[index+1] != '\n')
		bareNewline := value == '\n' && (index == 0 || data[index-1] != '\r')
		if value == 0 || bareReturn || bareNewline ||
			(value < 0x20 && value != '\r' && value != '\t' && value != '\n') || value == 0x7f {
			return request, 0, fmt.Errorf("%w: invalid control byte", errHTTPMalformed)
		}
	}

	lines := bytes.Split(data[:end], []byte("\r\n"))
	if len(lines) < 2 || len(lines)-1 > maxHTTPHeaders {
		return request, 0, fmt.Errorf("%w: invalid header count", errHTTPMalformed)
	}
	parts := bytes.Split(lines[0], []byte{' '})
	if len(parts) != 3 || len(parts[0]) == 0 || len(parts[1]) == 0 || !bytes.Equal(parts[2], []byte("HTTP/1.1")) {
		return request, 0, fmt.Errorf("%w: invalid request line", errHTTPMalformed)
	}
	if !validMethod(parts[0]) {
		return request, 0, fmt.Errorf("%w: invalid method", errHTTPMalformed)
	}
	request.method = string(parts[0])
	if err := parseRequestTarget(&request, parts[1]); err != nil {
		return carrierRequest{}, 0, err
	}

	request.headers = make(map[string]string, len(lines)-1)
	for _, line := range lines[1:] {
		if len(line) == 0 || line[0] == ' ' || line[0] == '\t' {
			return carrierRequest{}, 0, fmt.Errorf("%w: folded or empty header", errHTTPMalformed)
		}
		colon := bytes.IndexByte(line, ':')
		if colon <= 0 || !validHeaderName(line[:colon]) {
			return carrierRequest{}, 0, fmt.Errorf("%w: invalid header name", errHTTPMalformed)
		}
		name := strings.ToLower(string(line[:colon]))
		if _, duplicate := request.headers[name]; duplicate {
			return carrierRequest{}, 0, fmt.Errorf("%w: duplicate header", errHTTPMalformed)
		}
		value := strings.Trim(string(line[colon+1:]), " \t")
		if !validHeaderValue(value) {
			return carrierRequest{}, 0, fmt.Errorf("%w: invalid header value", errHTTPMalformed)
		}
		request.headers[name] = value
	}
	if request.headers["host"] == "" {
		return carrierRequest{}, 0, fmt.Errorf("%w: missing Host", errHTTPMalformed)
	}
	if _, exists := request.headers["transfer-encoding"]; exists {
		return carrierRequest{}, 0, fmt.Errorf("%w: Transfer-Encoding is unsupported", errHTTPMalformed)
	}
	if _, exists := request.headers["te"]; exists {
		return carrierRequest{}, 0, fmt.Errorf("%w: TE is unsupported", errHTTPMalformed)
	}
	if _, exists := request.headers["trailer"]; exists {
		return carrierRequest{}, 0, fmt.Errorf("%w: Trailer is unsupported", errHTTPMalformed)
	}
	if value, exists := request.headers["expect"]; exists && value != "" {
		return carrierRequest{}, 0, fmt.Errorf("%w: Expect is unsupported", errHTTPMalformed)
	}
	if value, exists := request.headers["content-length"]; exists {
		length, ok := canonicalDecimal(value)
		if !ok {
			return carrierRequest{}, 0, fmt.Errorf("%w: invalid Content-Length", errHTTPMalformed)
		}
		request.contentLength = length
		request.hasContentLength = true
	}
	closeConnection, upgradeConnection, validConnection := parseConnectionHeader(
		request.headers["connection"],
		request.headers["upgrade"],
	)
	if !validConnection {
		return carrierRequest{}, 0, fmt.Errorf("%w: unsupported Connection value", errHTTPMalformed)
	}
	request.close = closeConnection
	request.upgrade = upgradeConnection
	return request, headerBytes, nil
}

func parseConnectionHeader(value, upgrade string) (closeConnection, upgradeConnection, valid bool) {
	if value == "" {
		return false, false, true
	}

	var keepAlive, closeSeen, upgradeSeen bool
	for field := range strings.SplitSeq(value, ",") {
		token := strings.Trim(field, " \t")
		if token == "" || !validHeaderName([]byte(token)) {
			return false, false, false
		}
		switch {
		case strings.EqualFold(token, "keep-alive"):
			if keepAlive {
				return false, false, false
			}
			keepAlive = true
		case strings.EqualFold(token, "close"):
			if closeSeen {
				return false, false, false
			}
			closeSeen = true
		case strings.EqualFold(token, "upgrade"):
			if upgradeSeen {
				return false, false, false
			}
			upgradeSeen = true
		default:
			return false, false, false
		}
	}
	if closeSeen {
		return true, false, !keepAlive && !upgradeSeen
	}
	if upgradeSeen {
		return false, true, upgrade != ""
	}
	return false, false, keepAlive
}

func parseRequestTarget(request *carrierRequest, target []byte) error {
	if len(target) == 0 || target[0] != '/' || bytes.ContainsAny(target, "#\r\n\x00") {
		return fmt.Errorf("%w: invalid request target", errHTTPMalformed)
	}
	path, query, found := bytes.Cut(target, []byte{'?'})
	if len(path) == 0 {
		return fmt.Errorf("%w: empty request path", errHTTPMalformed)
	}
	request.path = string(path)
	if found {
		request.query = string(query)
	}
	return nil
}

func validMethod(value []byte) bool {
	for _, character := range value {
		if !isTokenCharacter(character) {
			return false
		}
	}
	return true
}

func validHeaderName(value []byte) bool {
	if len(value) == 0 {
		return false
	}
	for _, character := range value {
		if !isTokenCharacter(character) {
			return false
		}
	}
	return true
}

func isTokenCharacter(character byte) bool {
	if (character >= '0' && character <= '9') ||
		(character >= 'A' && character <= 'Z') ||
		(character >= 'a' && character <= 'z') {
		return true
	}
	switch character {
	case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
		return true
	default:
		return false
	}
}

func validHeaderValue(value string) bool {
	for index := 0; index < len(value); index++ {
		character := value[index]
		if character == 0x7f || (character < 0x20 && character != '\t') {
			return false
		}
	}
	return true
}

func canonicalDecimal(value string) (uint64, bool) {
	if value == "" || (len(value) > 1 && value[0] == '0') {
		return 0, false
	}
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil || strconv.FormatUint(parsed, 10) != value {
		return 0, false
	}
	return parsed, true
}

func bearerToken(value string) (string, bool) {
	const prefix = "Bearer "
	if !strings.HasPrefix(value, prefix) || strings.ContainsAny(value[len(prefix):], " \t") {
		return "", false
	}
	token := value[len(prefix):]
	if _, err := parseTokenHash(token); err != nil {
		return "", false
	}
	return token, true
}
