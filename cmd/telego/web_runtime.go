package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/scratch-net/telego/pkg/config"
	"github.com/scratch-net/telego/pkg/gproxy"
	"github.com/scratch-net/telego/pkg/webproxy"
)

const webProxyLifecycleTimeout = 5 * time.Second

// webProxyRuntime owns only the optional native WEB subsystem. The public
// MTProxy engine remains independent and is started by RunCmd as before.
type webProxyRuntime struct {
	manager *webproxy.Manager
	server  *webproxy.HTTPServer
}

func newWebProxyRuntime(runtimeConfig config.WebProxyRuntimeConfig, internalAuth *gproxy.InternalProxyAuth) (*webProxyRuntime, error) {
	if !runtimeConfig.Enabled {
		return nil, nil
	}
	if runtimeConfig.BackendProxyProtocol && internalAuth == nil {
		return nil, errors.New("create WEB session manager: internal backend authentication is required")
	}

	managerConfig := webproxy.DefaultManagerConfig(runtimeConfig.Profiles, runtimeConfig.Backend)
	if runtimeConfig.Carrier != "" {
		managerConfig.Carrier = runtimeConfig.Carrier
	}
	if runtimeConfig.BackendProxyProtocol {
		managerConfig.BackendDialContext = webProxyBackendDialer((&net.Dialer{}).DialContext, internalAuth)
	}
	manager, err := webproxy.NewManager(managerConfig)
	if err != nil {
		return nil, fmt.Errorf("create WEB session manager: %w", err)
	}
	server, err := webproxy.NewHTTPServer(webproxy.HTTPServerConfig{
		Bind:              runtimeConfig.BindAddr,
		Hostname:          runtimeConfig.Hostname,
		Manager:           manager,
		Multicore:         true,
		NumEventLoop:      runtimeConfig.NumEventLoops,
		TrustedProxyCIDRs: runtimeConfig.TrustedProxyCIDRs,
	})
	if err != nil {
		ctx, cancel := context.WithTimeout(context.Background(), webProxyLifecycleTimeout)
		defer cancel()
		return nil, errors.Join(fmt.Errorf("create WEB HTTP server: %w", err), manager.Shutdown(ctx))
	}
	return &webProxyRuntime{manager: manager, server: server}, nil
}

func webProxyBackendDialer(dial webproxy.DialContextFunc, internalAuth *gproxy.InternalProxyAuth) webproxy.BackendDialContextFunc {
	return func(ctx context.Context, network, address, clientIP string) (net.Conn, error) {
		if internalAuth == nil {
			return nil, errors.New("WEB backend authentication is not initialized")
		}
		connection, err := dial(ctx, network, address)
		if err != nil {
			return nil, err
		}
		header, err := internalProxyHeader(clientIP)
		if err != nil {
			_ = connection.Close()
			return nil, err
		}
		if deadline, ok := ctx.Deadline(); ok {
			if err := connection.SetWriteDeadline(deadline); err != nil {
				_ = connection.Close()
				return nil, fmt.Errorf("set WEB backend PROXY header deadline: %w", err)
			}
		}
		prefaceAndHeader := internalAuth.AppendPreface(make([]byte, 0, len(header)+64))
		prefaceAndHeader = append(prefaceAndHeader, header...)
		writeErr := writeAll(connection, prefaceAndHeader)
		clear(prefaceAndHeader)
		if writeErr != nil {
			_ = connection.Close()
			return nil, fmt.Errorf("write WEB backend PROXY header: %w", writeErr)
		}
		if err := connection.SetWriteDeadline(time.Time{}); err != nil {
			_ = connection.Close()
			return nil, fmt.Errorf("clear WEB backend PROXY header deadline: %w", err)
		}
		return connection, nil
	}
}

func internalProxyHeader(clientIP string) ([]byte, error) {
	address, err := netip.ParseAddr(clientIP)
	if err != nil || address.String() != clientIP {
		return nil, fmt.Errorf("invalid WEB backend client IP %q", clientIP)
	}
	if address.Is4() {
		return fmt.Appendf(nil, "PROXY TCP4 %s 127.0.0.1 0 0\r\n", address), nil
	}
	return fmt.Appendf(nil, "PROXY TCP6 %s ::1 0 0\r\n", address), nil
}

func writeAll(connection net.Conn, data []byte) error {
	for len(data) != 0 {
		written, err := connection.Write(data)
		if err != nil {
			return err
		}
		if written == 0 {
			return errors.New("WEB backend PROXY header write made no progress")
		}
		data = data[written:]
	}
	return nil
}

func (r *webProxyRuntime) Start(ctx context.Context) error {
	if r == nil {
		return nil
	}
	if err := r.server.Start(ctx); err != nil {
		return fmt.Errorf("start WEB HTTP server: %w", err)
	}
	return nil
}

func (r *webProxyRuntime) Errors() <-chan error {
	if r == nil {
		return nil
	}
	return r.server.Errors()
}

// Shutdown preserves dependency order: stop accepting WEB HTTP requests, stop
// all WEB sessions and backend streams, then let RunCmd stop the MTProxy engine.
func (r *webProxyRuntime) Shutdown(ctx context.Context) error {
	if r == nil {
		return nil
	}
	return errors.Join(r.server.Stop(ctx), r.manager.Shutdown(ctx))
}
