package config

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestGatewaySetupACMEWebrootPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("gateway setup requires POSIX shell and file modes")
	}
	shell, err := exec.LookPath("sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, repeat := range []bool{false, true} {
		name := "fresh"
		if repeat {
			name = "repair_existing_private_webroot"
		}
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			for _, path := range []string{
				"setup.sh", "compose.yaml", "nginx/watch-certificate.sh",
				"templates/telego.toml", "templates/nginx.conf",
				"templates/nginx-web-server.conf", "templates/index.html",
			} {
				data := gatewaySetupRead(t, filepath.Join("..", "..", "examples", "gateway", path))
				gatewaySetupWrite(t, filepath.Join(root, path), data, 0o600)
			}
			certificateDir := "state/letsencrypt/conf/live/proxy.example.com"
			for _, name := range []string{"fullchain.pem", "privkey.pem"} {
				gatewaySetupWrite(t, filepath.Join(root, certificateDir, name), []byte("local certificate fixture\n"), 0o600)
			}
			fakeBin := filepath.Join(root, "test-bin")
			gatewaySetupWrite(t, filepath.Join(fakeBin, "docker"), []byte(`#!/bin/sh
set -eu
case "$*" in
    'compose version' | 'compose ps') test "$#" -eq 2 ;;
    'info') test "$#" -eq 1 ;;
    'compose config --quiet' | 'compose up -d') test "$#" -eq 3 ;;
    'compose up -d nginx') test "$#" -eq 4 ;;
    'compose exec -T nginx nginx -t') test "$#" -eq 6 ;;
    *) exit 97 ;;
esac
printf '%s\n' "$*" >> "$GATEWAY_TEST_DOCKER_LOG"
`), 0o700)
			dockerLog := filepath.Join(root, "docker-calls")
			runSetup := func() {
				t.Helper()
				ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, shell, filepath.Join(root, "setup.sh"),
					"--domain", "proxy.example.com", "--email", "operator@example.com")
				cmd.Dir = root
				cmd.Env = append(os.Environ(), "PATH="+fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"),
					"GATEWAY_TEST_DOCKER_LOG="+dockerLog)
				// Setup prints generated secrets. Do not include its output in test failures.
				if err := cmd.Run(); err != nil {
					t.Fatalf("gateway setup failed: %v", err)
				}
			}
			unchanged := make(map[string][]byte)
			if repeat {
				runSetup()
				for _, path := range []string{
					"state/telego/config.toml", "state/links.txt",
					"state/nginx/nginx.conf", "state/nginx/gateway-server.conf",
					certificateDir + "/fullchain.pem", certificateDir + "/privkey.pem",
				} {
					unchanged[path] = gatewaySetupRead(t, filepath.Join(root, path))
				}
				if err := os.Chmod(filepath.Join(root, "state/letsencrypt/www"), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			runSetup()
			gatewaySetupMode(t, filepath.Join(root, "state/letsencrypt/www"), 0o755)
			gatewaySetupMode(t, filepath.Join(root, "state/site"), 0o755)
			gatewaySetupMode(t, filepath.Join(root, "state/nginx/watch-certificate.sh"), 0o755)
			for _, path := range []string{
				"state", "state/telego", "state/nginx", "state/letsencrypt",
				"state/letsencrypt/conf", "state/letsencrypt/lib", "state/letsencrypt/conf/live",
				certificateDir, "state/runtime",
			} {
				gatewaySetupMode(t, filepath.Join(root, path), 0o700)
			}
			for _, path := range []string{
				"state/telego/config.toml", "state/links.txt",
				certificateDir + "/fullchain.pem", certificateDir + "/privkey.pem",
			} {
				gatewaySetupMode(t, filepath.Join(root, path), 0o600)
			}
			for path, before := range unchanged {
				if !bytes.Equal(before, gatewaySetupRead(t, filepath.Join(root, path))) {
					t.Errorf("repeat setup changed %s", path)
				}
			}
			cfg, err := Load(filepath.Join(root, "state/telego/config.toml"))
			if err != nil {
				t.Fatalf("load generated configuration: %v", err)
			}
			proxyCfg, err := cfg.ToGProxyConfig()
			if err != nil {
				t.Fatalf("convert generated configuration: %v", err)
			}
			if len(proxyCfg.Secrets) != 1 || proxyCfg.BindAddr != "0.0.0.0:9443" || proxyCfg.MaskHost != "proxy.example.com" {
				t.Error("generated gateway configuration lost its secret or listener settings")
			}
			if _, err := cfg.ToWebProxyRuntimeConfig(proxyCfg.BindAddr); err != nil {
				t.Fatalf("convert generated WEB configuration: %v", err)
			}
			wantCalls := "compose version\ninfo\ncompose config --quiet\ncompose up -d nginx\ncompose exec -T nginx nginx -t\ncompose up -d\ncompose ps\n"
			if repeat {
				wantCalls = strings.Repeat(wantCalls, 2)
			}
			if !bytes.Equal(gatewaySetupRead(t, dockerLog), []byte(wantCalls)) {
				t.Error("gateway setup did not use the expected Docker command sequence")
			}
		})
	}
}

func gatewaySetupRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func gatewaySetupWrite(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
}

func gatewaySetupMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Errorf("%s mode = %#o, want %#o", path, got, want)
	}
}
