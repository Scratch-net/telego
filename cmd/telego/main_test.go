package main

import (
	"errors"
	"testing"

	"github.com/scratch-net/telego/pkg/log"
	"github.com/scratch-net/telego/pkg/webproxy"
)

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
