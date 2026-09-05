package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/scratch-net/telego/pkg/config"
	"github.com/scratch-net/telego/pkg/gproxy"
	"github.com/scratch-net/telego/pkg/webproxy"
)

const webProxyLifecycleTimeout = 5 * time.Second

// webProxyRuntime owns only the optional native WEB subsystem. The public
// MTProxy engine remains independent and is started by RunCmd as before.
type webProxyRuntime struct {
	manager      *webproxy.Manager
	server       *webproxy.HTTPServer
	shutdownOnce sync.Once
	shutdownDone chan struct{}
	shutdownErr  error
}

func newWebProxyRuntime(runtimeConfig config.WebProxyRuntimeConfig, internalAuth *gproxy.InternalProxyAuth, handler *gproxy.ProxyHandler) (*webProxyRuntime, error) {
	if !runtimeConfig.Enabled {
		return nil, nil
	}
	if runtimeConfig.BackendProxyProtocol && internalAuth == nil {
		return nil, errors.New("create WEB session manager: internal backend authentication is required")
	}
	if runtimeConfig.LogicalBackend && (handler == nil || runtimeConfig.MTProxyAddr == nil) {
		return nil, errors.New("create WEB session manager: logical backend requires the MTProxy handler and listener address")
	}

	managerConfig := webproxy.DefaultManagerConfig(runtimeConfig.Profiles, runtimeConfig.Backend)
	if runtimeConfig.Carrier != "" {
		managerConfig.Carrier = runtimeConfig.Carrier
	}
	if runtimeConfig.LogicalBackend {
		managerConfig.BackendFactory = webProxyLogicalBackendFactory(handler, runtimeConfig.MTProxyAddr)
	} else {
		var dial webproxy.BackendDialContextFunc
		if runtimeConfig.BackendProxyProtocol {
			dial = webProxyBackendDialer((&net.Dialer{}).DialContext, internalAuth)
		}
		managerConfig.BackendFactory = webproxy.GnetBackendFactory(dial)
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

func webProxyLogicalBackendFactory(handler *gproxy.ProxyHandler, listener net.Addr) webproxy.BackendFactory {
	return func(options webproxy.BackendOpenOptions) (webproxy.Backend, error) {
		if err := options.Context.Err(); err != nil {
			return nil, err
		}
		clientAddr, err := netip.ParseAddr(options.ClientIP)
		if err != nil || clientAddr.String() != options.ClientIP {
			return nil, fmt.Errorf("invalid logical WEB client IP %q", options.ClientIP)
		}
		var openingMu sync.Mutex
		var stream *gproxy.LogicalStream
		opened, canceled := false, false
		stopCancellation := context.AfterFunc(options.Context, func() {
			openingMu.Lock()
			if opened {
				openingMu.Unlock()
				return
			}
			canceled = true
			current := stream
			openingMu.Unlock()
			if current != nil {
				_ = current.Close()
			}
		})
		created, err := handler.OpenLogicalStream(gproxy.LogicalStreamOptions{
			Owner:          options.Owner,
			ClientAddr:     netip.AddrPortFrom(clientAddr, 0),
			LocalAddr:      listener,
			MaxInputBytes:  options.MaxInputBytes,
			MaxOutputBytes: options.MaxOutputBytes,
			MaxInputItems:  options.MaxInputItems,
			MaxOutputItems: options.MaxOutputItems,
			InputBudget: gproxy.LogicalQueueBudget{
				Reserve: options.InputBudget.Reserve, Release: options.InputBudget.Release,
			},
			OutputBudget: gproxy.LogicalQueueBudget{
				Reserve: options.OutputBudget.Reserve, Release: options.OutputBudget.Release,
			},
			Notify: options.Notify,
			OnOpened: func(err error) {
				openingMu.Lock()
				opened = true
				if contextErr := options.Context.Err(); contextErr != nil {
					canceled = true
					err = contextErr
				}
				closeCurrent, current := canceled, stream
				openingMu.Unlock()
				// The caller cancels its setup context on success. Retire the
				// watcher before forwarding that callback.
				stopCancellation()
				options.OnOpened(err)
				if closeCurrent && current != nil {
					_ = current.Close()
				}
			},
			OnClosed: options.OnClosed,
		})
		if err != nil {
			stopCancellation()
			return nil, err
		}
		openingMu.Lock()
		stream = created
		closeCreated := canceled
		openingMu.Unlock()
		if closeCreated {
			_ = created.Close()
		}
		return created, nil
	}
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

// Shutdown closes sessions while their HTTP owner loops still run, then stops
// the HTTP engine. RunCmd stops the public MTProxy engine afterwards.
func (r *webProxyRuntime) Shutdown(ctx context.Context) error {
	if r == nil {
		return nil
	}
	r.shutdownOnce.Do(func() {
		r.shutdownDone = make(chan struct{})
		go func() {
			// Caller cancellation limits waiting, not the lifetime of owner
			// loops needed to release sessions and queued backend resources.
			r.shutdownErr = r.manager.Shutdown(context.Background())
			if r.shutdownErr == nil {
				r.shutdownErr = r.server.Stop(context.Background())
			}
			close(r.shutdownDone)
		}()
	})
	select {
	case <-r.shutdownDone:
		return r.shutdownErr
	case <-ctx.Done():
		return ctx.Err()
	}
}
