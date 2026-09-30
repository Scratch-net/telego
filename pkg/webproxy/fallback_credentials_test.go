package webproxy

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestHTTPCredentialVariantsUseSanitizedFallback(t *testing.T) {
	for _, basePath := range []string{"", "telegram/test"} {
		t.Run(basePath, func(t *testing.T) {
			profiles, err := DeriveProfilesForPath("fallback", "proxy.example.com", basePath, []byte("0123456789abcdef"))
			if err != nil {
				t.Fatal(err)
			}
			app := newHTTPTestApplicationWithConfig(t, time.Second, func(c *ManagerConfig) {
				c.Profiles = profiles[:]
			}, func(c *HTTPServerConfig) { c.BasePath = basePath })
			client := &http.Client{Timeout: time.Second}
			prefix := ""
			if basePath != "" {
				prefix = "/" + basePath
			}
			capability := profiles[0].Capability().String()
			encoded := fmt.Sprintf("%%%02X%s", capability[0], capability[1:])
			for name, target := range map[string]string{
				"encoded key at bridge":       prefix + "/?br%69dge=" + capability,
				"encoded value at bridge":     prefix + "/?bridge=" + encoded,
				"encoded key at wrong path":   "/ordinary?br%69dge=" + capability,
				"encoded value at wrong path": "/ordinary?bridge=" + encoded,
				"duplicate bridge":            "/ordinary?bridge=invalid&br%69dge=" + capability,
				"invalid unrelated escape":    "/ordinary?invalid=%zz&br%69dge=" + capability,
			} {
				t.Run(name, func(t *testing.T) {
					response := app.do(t, client, http.MethodGet, target, nil, nil)
					_ = readHTTPBody(t, response)
					if response.StatusCode != defaultSanitizedFallbackStatus {
						t.Fatalf("credential request received status %d", response.StatusCode)
					}
				})
			}
			for index, alias := range fallbackCredentialAliases(t, capability) {
				t.Run(fmt.Sprintf("bridge alias %d", index), func(t *testing.T) {
					response := app.do(t, client, http.MethodGet, "/ordinary?bridge="+url.QueryEscape(alias), nil, nil)
					_ = readHTTPBody(t, response)
					if response.StatusCode != defaultSanitizedFallbackStatus {
						t.Fatalf("bridge alias received status %d", response.StatusCode)
					}
				})
			}

			bootstrap, err := app.manager.IssueBootstrap(profiles[0].Capability(), "192.0.2.1")
			if err != nil {
				t.Fatal(err)
			}
			created := createTestSession(t, app.manager, profiles[0])
			for name, token := range map[string]string{"bootstrap": bootstrap, "session": created.Token} {
				for _, scheme := range []string{"Bearer ", "bearer ", "bEaReR\t", "BEARER   "} {
					t.Run(name+"/"+strings.TrimSpace(scheme), func(t *testing.T) {
						response := app.do(t, client, http.MethodGet, "/ordinary", nil, map[string]string{"Authorization": scheme + token})
						_ = readHTTPBody(t, response)
						if response.StatusCode != defaultSanitizedFallbackStatus {
							t.Fatalf("known bearer received status %d", response.StatusCode)
						}
					})
				}
				for index, alias := range fallbackCredentialAliases(t, token) {
					t.Run(fmt.Sprintf("%s alias %d", name, index), func(t *testing.T) {
						response := app.do(t, client, http.MethodGet, "/ordinary", nil, map[string]string{"Authorization": "Bearer " + alias})
						_ = readHTTPBody(t, response)
						if response.StatusCode != defaultSanitizedFallbackStatus {
							t.Fatalf("bearer alias received status %d", response.StatusCode)
						}
					})
				}
			}
			// Detection must not relax authorization or retire a live session.
			response := app.do(t, client, http.MethodDelete, prefix+"/api/v1/session", nil, map[string]string{"Authorization": "bearer " + created.Token})
			_ = readHTTPBody(t, response)
			if response.StatusCode != defaultSanitizedFallbackStatus {
				t.Fatalf("alternate bearer scheme authorized deletion: %d", response.StatusCode)
			}
			if _, err := app.manager.Get(created.Token); err != nil {
				t.Fatal("fallback retired the live session")
			}
			for _, alias := range fallbackCredentialAliases(t, created.Token) {
				response := app.do(t, client, http.MethodDelete, prefix+"/api/v1/session", nil, map[string]string{"Authorization": "Bearer " + alias})
				_ = readHTTPBody(t, response)
				if response.StatusCode != defaultSanitizedFallbackStatus {
					t.Fatalf("bearer alias authorized deletion: %d", response.StatusCode)
				}
				if _, err := app.manager.Get(created.Token); err != nil {
					t.Fatal("bearer alias retired the live session")
				}
			}
			created.Session.Close()
			created.Session.wait()
			if app.manager.Capacity().ClosedTokens != 1 {
				t.Fatal("closed token was not retained")
			}
			response = app.do(t, client, http.MethodGet, "/ordinary", nil, map[string]string{"Authorization": "Bearer " + created.Token})
			_ = readHTTPBody(t, response)
			if response.StatusCode != defaultSanitizedFallbackStatus {
				t.Fatalf("retired bearer received status %d", response.StatusCode)
			}

			// Unrelated website credentials still belong to the ordinary fallback.
			unknown, _, err := newToken()
			if err != nil {
				t.Fatal(err)
			}
			for _, target := range []string{"/ordinary", "/ordinary?br%69dge=" + unknown, "/ordinary?bridge=%zz", "/?site=value"} {
				response := app.do(t, client, http.MethodGet, target, nil, map[string]string{"Authorization": "Bearer " + unknown})
				_ = readHTTPBody(t, response)
				if response.StatusCode != defaultPassthroughStatus {
					t.Fatalf("ordinary request received status %d", response.StatusCode)
				}
			}
		})
	}
}

func fallbackCredentialAliases(t *testing.T, canonical string) []string {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(canonical)
	if err != nil || len(raw) != 32 {
		t.Fatal("invalid canonical test credential")
	}
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	tail := strings.IndexByte(alphabet, canonical[len(canonical)-1])
	noncanonical := canonical[:len(canonical)-1] + string(alphabet[tail|1])
	aliases := []string{noncanonical, canonical + "=", noncanonical + "=", base64.StdEncoding.EncodeToString(raw)}
	standard := base64.RawStdEncoding.EncodeToString(raw)
	if standard != canonical {
		aliases = append(aliases, standard)
	}
	return aliases
}
