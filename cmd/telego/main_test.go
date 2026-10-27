package main

import (
	"bytes"
	"encoding/json/v2"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"

	"github.com/scratch-net/telego/pkg/log"
	"github.com/scratch-net/telego/pkg/webproxy"
)

func TestMainFlushesCLIOutput(t *testing.T) {
	if mode := os.Getenv("TELEGO_TEST_MAIN_LOGGING"); mode != "" {
		log.SetJSON()
		if mode == "version" {
			os.Args = []string{"telego", "version"}
		} else {
			os.Args = []string{"telego", "run", "--config", mode}
		}
		main()
		os.Exit(0)
	}
	invalidConfig := filepath.Join(t.TempDir(), "invalid.toml")
	if err := os.WriteFile(invalidConfig, []byte("broken = ["), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		mode    string
		message string
		code    int
	}{
		{"version", `"message":"telego"`, 0},
		{invalidConfig, `"message":"failed to load config"`, 1},
	} {
		command := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestMainFlushesCLIOutput$")
		command.Env = append(os.Environ(), "TELEGO_TEST_MAIN_LOGGING="+tc.mode)
		output, err := command.CombinedOutput()
		code := 0
		if err != nil {
			exitErr, ok := errors.AsType[*exec.ExitError](err)
			if !ok {
				t.Fatalf("command failed: %v", err)
			}
			code = exitErr.ExitCode()
		}
		if code != tc.code || !bytes.Contains(output, []byte(tc.message)) {
			t.Fatalf("mode %q: exit %d, want %d; output %s", tc.mode, code, tc.code, output)
		}
	}
}

func TestVersionCmdFeatures(t *testing.T) {
	// Isolate the global logger and capture the command's structured output.
	if os.Getenv("TELEGO_TEST_VERSION_COMMAND") == "1" {
		log.SetJSON()
		if err := new(VersionCmd).Run(); err != nil {
			_ = log.Close()
			os.Exit(1)
		}
		_ = log.Close()
		os.Exit(0)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(t.Context(), executable, "-test.run=^TestVersionCmdFeatures$")
	command.Env = append(os.Environ(), "TELEGO_TEST_VERSION_COMMAND=1")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("version command: %v\n%s", err, output)
	}
	var record struct {
		Version  string   `json:"version"`
		Commit   string   `json:"commit"`
		Date     string   `json:"date"`
		Features []string `json:"features"`
	}
	if err := json.Unmarshal(output, &record); err != nil {
		t.Fatalf("decode version output: %v", err)
	}
	if record.Version != version || record.Commit != commit || record.Date != date {
		t.Errorf("build metadata changed: %+v", record)
	}
	if !slices.Contains(record.Features, "Named secrets with per-user tracking") {
		t.Error("version output does not describe named secrets")
	}
	if slices.Contains(record.Features, "Multiple secrets per user") {
		t.Error("version output claims multiple secrets per user")
	}
}

func TestGenerateCmdWithWebHost(t *testing.T) {
	log.SetLevel("disabled")
	t.Cleanup(func() { log.SetLevel("info") })

	command := GenerateCmd{
		Host:    "www.google.com",
		WebHost: "proxy.example.com",
	}
	if err := command.Run(); err != nil {
		t.Fatalf("Run: %v", err)
	}
}

func TestGenerateCmdRejectsInvalidWebHost(t *testing.T) {
	command := GenerateCmd{
		Host:    "www.google.com",
		WebHost: "https://proxy.example.com",
	}
	err := command.Run()
	if !errors.Is(err, webproxy.ErrInvalidHostname) {
		t.Fatalf("Run error = %v, want ErrInvalidHostname", err)
	}
}
