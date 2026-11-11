package main

import (
	"net"
	"testing"

	"github.com/pion/stun/v4"
)

// serveOneSTUNResponse answers one binding request with the given attributes.
func serveOneSTUNResponse(t *testing.T, setters ...stun.Setter) string {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	go func() {
		buffer := make([]byte, 1500)
		n, peer, err := conn.ReadFrom(buffer)
		if err != nil {
			return
		}
		request := &stun.Message{Raw: append([]byte(nil), buffer[:n]...)}
		if request.Decode() != nil {
			return
		}
		response, err := stun.Build(append([]stun.Setter{
			stun.NewTransactionIDSetter(request.TransactionID), stun.BindingSuccess,
		}, setters...)...)
		if err != nil {
			return
		}
		_, _ = conn.WriteTo(response.Raw, peer)
	}()
	return conn.LocalAddr().String()
}

func TestGetPublicIPReportsMissingMappedAddress(t *testing.T) {
	ip, err := getPublicIPFrom(serveOneSTUNResponse(t))
	if err == nil {
		t.Fatalf("STUN response without a mapped address returned ip=%q and no error", ip)
	}
}

func TestGetPublicIPReturnsMappedAddress(t *testing.T) {
	mapped := &stun.XORMappedAddress{IP: net.IPv4(203, 0, 113, 7), Port: 4242}
	ip, err := getPublicIPFrom(serveOneSTUNResponse(t, mapped))
	if err != nil || ip != "203.0.113.7" {
		t.Fatalf("getPublicIPFrom = %q, %v; want 203.0.113.7", ip, err)
	}
}
