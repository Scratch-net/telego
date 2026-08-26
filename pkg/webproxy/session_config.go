package webproxy

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	queueItemCost                = 256
	controlReserveExtraItems     = 16
	controlReserveItemsPerStream = 3
	maxCarrierBatchBytes         = 2 * 1024 * 1024
)

var ErrInvalidManagerConfig = errors.New("invalid WEB session manager configuration")

// DialContextFunc opens the fixed backend connection for one WEB stream.
type DialContextFunc func(ctx context.Context, network, address string) (net.Conn, error)

// BackendDialContextFunc opens one WEB backend stream with its validated client
// IP. Integrations use this seam to prepend a trusted internal PROXY header.
type BackendDialContextFunc func(ctx context.Context, network, address, clientIP string) (net.Conn, error)

// Limits bounds every resource owned by the serialized HTTPS session manager.
// Start with DefaultLimits and change only values that an operator needs to tune.
type Limits struct {
	CarrierBatchBytes         int
	MaxBodyBytes              int
	MaxStreamsPerSession      int
	MaxClosedStreamIDs        int
	MaxPendingPerSession      int
	MaxPendingGlobal          int
	MaxPendingItemsPerSession int
	MaxPendingItemsGlobal     int
	MaxBootstraps             int
	MaxSessions               int
	MaxClosedTokens           int
	MaxStreams                int
	MaxBackendDialsInFlight   int
}

// DefaultLimits returns the protocol reference defaults for serialized HTTPS.
func DefaultLimits() Limits {
	return Limits{
		CarrierBatchBytes:         2 * 1024 * 1024,
		MaxBodyBytes:              2 * 1024 * 1024,
		MaxStreamsPerSession:      128,
		MaxClosedStreamIDs:        4096,
		MaxPendingPerSession:      32 * 1024 * 1024,
		MaxPendingGlobal:          512 * 1024 * 1024,
		MaxPendingItemsPerSession: 16 * 1024,
		MaxPendingItemsGlobal:     256 * 1024,
		MaxBootstraps:             512,
		MaxSessions:               128,
		MaxClosedTokens:           2048,
		MaxStreams:                4096,
		MaxBackendDialsInFlight:   256,
	}
}

// Timeouts controls backend establishment, long polling, and disconnected
// session retention.
type Timeouts struct {
	BackendDial       time.Duration
	LongPoll          time.Duration
	ReconnectGrace    time.Duration
	BootstrapLifetime time.Duration
}

// DefaultTimeouts returns the protocol reference defaults.
func DefaultTimeouts() Timeouts {
	return Timeouts{
		BackendDial:       5 * time.Second,
		LongPoll:          25 * time.Second,
		ReconnectGrace:    2 * time.Minute,
		BootstrapLifetime: 2 * time.Minute,
	}
}

// ManagerConfig supplies the already-derived WEB profiles and the one local
// backend accepted for every logical stream. Backend can be numeric loopback
// TCP or an absolute Unix-socket path, with an optional unix:// prefix.
type ManagerConfig struct {
	Profiles           []Profile
	Backend            string
	Carrier            CarrierMode
	Limits             Limits
	Timeouts           Timeouts
	DialContext        DialContextFunc
	BackendDialContext BackendDialContextFunc
}

// DefaultManagerConfig constructs a complete configuration using the protocol
// reference limits and the standard library TCP dialer.
func DefaultManagerConfig(profiles []Profile, backend string) ManagerConfig {
	return ManagerConfig{
		Profiles: profiles,
		Backend:  backend,
		Carrier:  CarrierHTTPS,
		Limits:   DefaultLimits(),
		Timeouts: DefaultTimeouts(),
	}
}

func validateManagerConfig(config ManagerConfig) error {
	if len(config.Profiles) == 0 {
		return fmt.Errorf("%w: at least one profile is required", ErrInvalidManagerConfig)
	}
	capabilities := make(map[Capability]struct{}, len(config.Profiles))
	for _, profile := range config.Profiles {
		capability := profile.Capability()
		if _, exists := capabilities[capability]; exists {
			return fmt.Errorf("%w: duplicate capability for profile %q", ErrInvalidManagerConfig, profile.Name())
		}
		capabilities[capability] = struct{}{}
	}
	if _, _, err := parseLocalBackend(config.Backend); err != nil {
		return fmt.Errorf("%w: backend: %v", ErrInvalidManagerConfig, err)
	}
	if !config.Carrier.valid() {
		return fmt.Errorf("%w: unsupported carrier mode %q", ErrInvalidManagerConfig, config.Carrier)
	}

	limits := config.Limits
	positive := []int{
		limits.CarrierBatchBytes,
		limits.MaxBodyBytes,
		limits.MaxStreamsPerSession,
		limits.MaxClosedStreamIDs,
		limits.MaxPendingPerSession,
		limits.MaxPendingGlobal,
		limits.MaxPendingItemsPerSession,
		limits.MaxPendingItemsGlobal,
		limits.MaxBootstraps,
		limits.MaxSessions,
		limits.MaxClosedTokens,
		limits.MaxStreams,
		limits.MaxBackendDialsInFlight,
	}
	for _, value := range positive {
		if value <= 0 {
			return fmt.Errorf("%w: all limits must be positive", ErrInvalidManagerConfig)
		}
	}
	if limits.CarrierBatchBytes > maxCarrierBatchBytes || limits.CarrierBatchBytes > limits.MaxBodyBytes {
		return fmt.Errorf("%w: carrier batch exceeds the configured body limit or 2 MiB protocol cap", ErrInvalidManagerConfig)
	}
	if limits.MaxPendingGlobal < limits.MaxPendingPerSession ||
		limits.MaxPendingItemsGlobal < limits.MaxPendingItemsPerSession ||
		limits.MaxStreams < limits.MaxStreamsPerSession ||
		limits.MaxStreams < limits.MaxBackendDialsInFlight {
		return fmt.Errorf("%w: global limits must not be smaller than their local limits", ErrInvalidManagerConfig)
	}
	reserveCost, reserveItems, ok := pendingControlReserve(limits)
	if !ok || reserveCost > limits.MaxPendingPerSession || reserveItems > limits.MaxPendingItemsPerSession {
		return fmt.Errorf("%w: per-session pending limits cannot hold control-frame reserve", ErrInvalidManagerConfig)
	}
	globalReserveCost, okCost := checkedMulInt(reserveCost, limits.MaxSessions)
	globalReserveItems, okItems := checkedMulInt(reserveItems, limits.MaxSessions)
	if !okCost || !okItems || globalReserveCost >= limits.MaxPendingGlobal || globalReserveItems >= limits.MaxPendingItemsGlobal {
		return fmt.Errorf("%w: session control reserves exhaust global pending limits", ErrInvalidManagerConfig)
	}
	if _, _, ok := pendingUplinkReserve(limits); !ok {
		return fmt.Errorf("%w: uplink reserve overflows", ErrInvalidManagerConfig)
	}

	timeouts := config.Timeouts
	if timeouts.BackendDial <= 0 || timeouts.LongPoll <= 0 ||
		timeouts.ReconnectGrace <= 0 || timeouts.BootstrapLifetime <= 0 {
		return fmt.Errorf("%w: all timeouts must be positive", ErrInvalidManagerConfig)
	}
	return nil
}

func parseLocalBackend(address string) (network, target string, err error) {
	if strings.HasPrefix(address, "unix://") || strings.HasPrefix(address, "/") {
		target = strings.TrimPrefix(address, "unix://")
		if !filepath.IsAbs(target) || target == "/" {
			return "", "", errors.New("unix backend must use an absolute socket path")
		}
		return "unix", target, nil
	}
	address = strings.TrimPrefix(address, "tcp://")
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", "", err
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return "", "", errors.New("TCP backend must use a numeric loopback address")
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return "", "", errors.New("invalid port")
	}
	return "tcp", net.JoinHostPort(host, port), nil
}

func pendingControlReserve(limits Limits) (int, int, bool) {
	streamItems, ok := checkedMulInt(limits.MaxStreamsPerSession, controlReserveItemsPerStream)
	if !ok {
		return 0, 0, false
	}
	items, ok := checkedAddInt(controlReserveExtraItems, streamItems)
	if !ok {
		return 0, 0, false
	}
	costPerItem := queueItemCost + FrameHeaderSize + 4
	cost, ok := checkedMulInt(items, costPerItem)
	return cost, items, ok
}

func pendingUplinkReserve(limits Limits) (int, int, bool) {
	items := min(limits.MaxBodyBytes/FrameHeaderSize, MaxBatchFrames)
	overhead, ok := checkedMulInt(items, queueItemCost)
	if !ok {
		return 0, 0, false
	}
	cost, ok := checkedAddInt(limits.MaxBodyBytes, overhead)
	return cost, items, ok
}

func checkedAddInt(left, right int) (int, bool) {
	if left < 0 || right < 0 || left > math.MaxInt-right {
		return 0, false
	}
	return left + right, true
}

func checkedMulInt(left, right int) (int, bool) {
	if left < 0 || right < 0 || (left != 0 && right > math.MaxInt/left) {
		return 0, false
	}
	return left * right, true
}

type boundedSet[T comparable] struct {
	values map[T]struct{}
	order  []T
	next   int
}

func newBoundedSet[T comparable](capacity int) boundedSet[T] {
	return boundedSet[T]{
		values: make(map[T]struct{}, capacity),
		order:  make([]T, 0, capacity),
	}
}

func (s *boundedSet[T]) Contains(value T) bool {
	_, exists := s.values[value]
	return exists
}

func (s *boundedSet[T]) Add(value T) (evicted T, didEvict bool) {
	if s.Contains(value) {
		return evicted, false
	}
	if len(s.order) < cap(s.order) {
		s.order = append(s.order, value)
	} else {
		evicted = s.order[s.next]
		delete(s.values, evicted)
		s.order[s.next] = value
		s.next = (s.next + 1) % len(s.order)
		didEvict = true
	}
	s.values[value] = struct{}{}
	return evicted, didEvict
}
