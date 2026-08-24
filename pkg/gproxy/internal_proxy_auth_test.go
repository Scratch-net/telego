package gproxy

import (
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"testing"
)

func TestInternalProxyAuthConcurrentUse(t *testing.T) {
	auth, err := NewInternalProxyAuth()
	if err != nil {
		t.Fatal(err)
	}

	const workers = 32
	var waitGroup sync.WaitGroup
	waitGroup.Add(workers)
	for range workers {
		go func() {
			defer waitGroup.Done()
			for range 100 {
				preface := auth.AppendPreface(nil)
				if auth.prefaceStatus(preface) != internalPrefaceAccepted {
					t.Error("generated preface was not accepted")
					return
				}
			}
		}()
	}
	waitGroup.Wait()
}

func TestInternalProxyAuthFormattingIsRedacted(t *testing.T) {
	auth, err := NewInternalProxyAuth()
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprintf("%v %#v", auth, auth); got != "[redacted] gproxy.InternalProxyAuth([redacted])" {
		t.Fatalf("formatted auth = %q", got)
	}
	formattedConfig := fmt.Sprintf("%+v", Config{InternalProxyAuth: auth})
	if strings.Contains(formattedConfig, hex.EncodeToString(auth.token[:])) {
		t.Fatal("formatted gproxy configuration disclosed the internal authentication token")
	}
}
