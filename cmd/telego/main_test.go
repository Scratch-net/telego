package main

import (
	"encoding/json/v2"
	"errors"
	"os"
	"os/exec"
	"slices"
	"testing"

	"github.com/scratch-net/telego/pkg/log"
	"github.com/scratch-net/telego/pkg/webproxy"
)

func TestVersionCmdFeatures(t *testing.T) {
	// Isolate the global logger and capture the command's structured output.
	if os.Getenv("TELEGO_TEST_VERSION_COMMAND") == "1" {
		log.SetJSON()
		if err := new(VersionCmd).Run(); err != nil {
			os.Exit(1)
		}
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
