package main

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/scratch-net/telego/pkg/transport/middleend"
)

func TestParseSignedDC(t *testing.T) {
	if dc, err := parseDC(""); err != nil || dc != nil {
		t.Fatalf("empty DC = %v, %v", dc, err)
	}
	for _, value := range []string{"-203", "0", "5", "32767", "-32768"} {
		dc, err := parseDC(value)
		if err != nil || dc == nil {
			t.Fatalf("parseDC(%q) = %v, %v", value, dc, err)
		}
	}
	for _, value := range []string{"32768", "-32769", "x"} {
		if _, err := parseDC(value); err == nil {
			t.Fatalf("parseDC(%q) succeeded", value)
		}
	}
}

func TestParseFamily(t *testing.T) {
	tests := map[string]middleend.AddressFamily{
		"any":  middleend.AddressFamilyAny,
		"4":    middleend.AddressFamilyIPv4,
		"IPv4": middleend.AddressFamilyIPv4,
		"6":    middleend.AddressFamilyIPv6,
		"ipv6": middleend.AddressFamilyIPv6,
	}
	for input, want := range tests {
		got, err := parseFamily(input)
		if err != nil || got != want {
			t.Fatalf("parseFamily(%q) = %d, %v, want %d", input, got, err, want)
		}
	}
	if _, err := parseFamily("auto"); err == nil {
		t.Fatal("invalid family succeeded")
	}
}

func TestSOCKSCredentialsFromEnvironment(t *testing.T) {
	t.Setenv(socksUsernameEnvironment, "user")
	t.Setenv(socksPasswordEnvironment, "password")
	credentials, err := socksCredentialsFromEnvironment()
	if err != nil {
		t.Fatalf("socksCredentialsFromEnvironment: %v", err)
	}
	if credentials.Username != "user" || credentials.Password != "password" {
		t.Fatal("credential values differ")
	}
}

func TestSOCKSCredentialsRequirePair(t *testing.T) {
	t.Setenv(socksUsernameEnvironment, "user")
	t.Setenv(socksPasswordEnvironment, "")
	if _, err := socksCredentialsFromEnvironment(); err == nil {
		t.Fatal("unpaired credentials succeeded")
	}
}

func TestRunMainRejectsUnsafeArgumentsBeforeNetwork(t *testing.T) {
	tests := [][]string{
		{"-artifact-timeout=0s"},
		{"-link-timeout=-1s"},
		{"positional"},
	}
	for _, arguments := range tests {
		if err := runMain(arguments); err == nil {
			t.Fatalf("runMain(%q) succeeded", arguments)
		}
	}
}

func TestRunMainHelpSucceedsWithoutNetwork(t *testing.T) {
	if err := runMain([]string{"-help"}); err != nil {
		t.Fatalf("runMain help: %v", err)
	}
}

func TestRunMainSanitizesInlineProxyCredentialsBeforeNetwork(t *testing.T) {
	tests := []struct {
		name      string
		argument  string
		guidance  []string
		wantError error
	}{
		{
			name:      "SOCKS5",
			argument:  "-socks=SECRET_MARKER:password@127.0.0.1:1080",
			guidance:  []string{socksUsernameEnvironment, socksPasswordEnvironment},
			wantError: middleend.ErrSOCKS5Address,
		},
		{name: "HTTP", argument: "-http-proxy=http://SECRET_MARKER:password@127.0.0.1:8080"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := runMain([]string{test.argument})
			if err == nil {
				t.Fatal("inline proxy credentials succeeded")
			}
			if test.wantError != nil && !errors.Is(err, test.wantError) {
				t.Errorf("CLI error = %v, want errors.Is(_, %v)", err, test.wantError)
			}
			if strings.Contains(err.Error(), "SECRET_MARKER") {
				t.Fatalf("CLI error exposed credential marker: %v", err)
			}
			for _, guidance := range test.guidance {
				if !strings.Contains(err.Error(), guidance) {
					t.Errorf("CLI error %q lacks guidance %q", err, guidance)
				}
			}
		})
	}
}

func TestInvalidOptionsNeverConstructArtifactSourceOrTransport(t *testing.T) {
	valid := options{
		family:          "any",
		endpointIndex:   0,
		artifactTimeout: defaultArtifactTimeout,
		linkTimeout:     defaultLinkTimeout,
	}
	noEnvironment := func(string) (string, bool) { return "", false }
	usernameOnly := func(name string) (string, bool) {
		if name == socksUsernameEnvironment {
			return "user", true
		}
		return "", false
	}
	emptyPassword := func(name string) (string, bool) {
		switch name {
		case socksUsernameEnvironment:
			return "user", true
		case socksPasswordEnvironment:
			return "", true
		default:
			return "", false
		}
	}
	tests := []struct {
		name      string
		mutate    func(*options)
		lookupEnv func(string) (string, bool)
		forbidden string
		required  []string
	}{
		{name: "artifact timeout", mutate: func(config *options) { config.artifactTimeout = 0 }},
		{name: "link timeout", mutate: func(config *options) { config.linkTimeout = -1 }},
		{name: "DC", mutate: func(config *options) { config.dc = "not-a-dc" }},
		{name: "family", mutate: func(config *options) { config.family = "auto" }},
		{name: "endpoint index", mutate: func(config *options) { config.endpointIndex = -1 }},
		{name: "HTTP proxy syntax", mutate: func(config *options) { config.httpProxy = "http://%zzSECRET_MARKER" }, forbidden: "SECRET_MARKER"},
		{name: "artifact proxy scheme", mutate: func(config *options) { config.httpProxy = "ftp://127.0.0.1:1080" }},
		{name: "artifact proxy path", mutate: func(config *options) { config.httpProxy = "socks5h://127.0.0.1:1080/path" }},
		{name: "HTTP proxy userinfo", mutate: func(config *options) { config.httpProxy = "http://SECRET_MARKER:password@127.0.0.1:8080" }, forbidden: "SECRET_MARKER"},
		{name: "SOCKS address", mutate: func(config *options) { config.socksAddress = "missing-port" }},
		{
			name: "inline SOCKS credentials",
			mutate: func(config *options) {
				config.socksAddress = "SECRET_MARKER:password@127.0.0.1:1080"
			},
			forbidden: "SECRET_MARKER",
			required:  []string{socksUsernameEnvironment, socksPasswordEnvironment},
		},
		{name: "unpaired SOCKS environment", lookupEnv: usernameOnly},
		{name: "empty SOCKS environment", lookupEnv: emptyPassword},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := valid
			if test.mutate != nil {
				test.mutate(&config)
			}
			lookupEnv := test.lookupEnv
			if lookupEnv == nil {
				lookupEnv = noEnvironment
			}
			var sourceCalls atomic.Int64
			var transportCalls atomic.Int64
			dependencies := runtimeDependencies{
				lookupEnv: lookupEnv,
				newHTTPTransport: func() *http.Transport {
					transportCalls.Add(1)
					return http.DefaultTransport.(*http.Transport).Clone()
				},
				newArtifactSource: func(*http.Client) (middleend.ArtifactSource, error) {
					sourceCalls.Add(1)
					return nil, errors.New("artifact source construction reached")
				},
			}
			err := runWithDependencies(t.Context(), config, io.Discard, dependencies)
			if err == nil {
				t.Fatal("invalid options succeeded")
			}
			if test.forbidden != "" && strings.Contains(err.Error(), test.forbidden) {
				t.Fatalf("validation error exposed input marker: %v", err)
			}
			for _, required := range test.required {
				if !strings.Contains(err.Error(), required) {
					t.Errorf("validation error %q lacks guidance %q", err, required)
				}
			}
			if got := sourceCalls.Load(); got != 0 {
				t.Fatalf("artifact source/transport constructed %d times", got)
			}
			if got := transportCalls.Load(); got != 0 {
				t.Fatalf("HTTP transport constructed %d times", got)
			}
		})
	}
}

func TestValidateOptionsAcceptsSOCKSArtifactProxy(t *testing.T) {
	config := options{
		family:          "any",
		endpointIndex:   0,
		httpProxy:       "socks5h://127.0.0.1:1080",
		artifactTimeout: defaultArtifactTimeout,
		linkTimeout:     defaultLinkTimeout,
	}
	validated, err := validateOptions(config, func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatalf("validateOptions: %v", err)
	}
	if validated.httpProxy == nil || validated.httpProxy.Scheme != "socks5h" {
		t.Fatalf("artifact proxy = %v", validated.httpProxy)
	}
}

func TestOptionsFormattingRedactsProxyConfiguration(t *testing.T) {
	config := options{
		dc: "-203", family: "4", endpointIndex: 7,
		socksAddress:    "proxy-address-must-not-appear:1080",
		httpProxy:       "http://http-proxy-must-not-appear:8080",
		artifactTimeout: time.Second, linkTimeout: time.Second,
	}
	validated := validatedOptions{endpointIndex: 7}
	for name, value := range map[string]any{
		"options value": config, "options pointer": &config,
		"validated value": validated, "validated pointer": &validated,
	} {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			output := fmt.Sprintf(format, value)
			if !strings.Contains(output, "redacted") || strings.Contains(output, "must-not-appear") {
				t.Fatalf("%s with %s was unsafe: %s", name, format, output)
			}
		}
	}
}
