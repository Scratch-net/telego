package main

import (
	"strconv"
	"sync"
	"time"

	"github.com/scratch-net/telego/pkg/gproxy"
	"github.com/scratch-net/telego/pkg/log"
	"github.com/scratch-net/telego/pkg/transport/middleend"
)

const middleEndMonitorInterval = 5 * time.Second

type middleEndMonitor struct {
	service  *middleend.Service
	frontend middleEndFrontendStatsProvider
	stop     chan struct{}
	stopper  sync.Once
	workers  sync.WaitGroup

	previous middleEndMonitorCounters
	pressure map[string]middleEndPressureState
}

type middleEndMonitorCounters struct {
	initialized                 bool
	admitting                   bool
	repairing                   bool
	refreshFailures             uint64
	generationFailures          uint64
	natIPv4Successes            uint64
	natIPv4Failures             uint64
	natIPv6Successes            uint64
	natIPv6Failures             uint64
	slotFailures                uint64
	slotFailureAffectedBindings uint64
	slotRepairSuccesses         uint64
	slotRepairFailures          uint64
	responseBackpressure        uint64
	controlBackpressure         uint64
	frontendInputPressure       uint64
	frontendOutputPressure      uint64
	frontendOutputEvictions     uint64
	middleEndBindingsTotal      uint64
	directFallbacksActive       int64
	directFallbacksTotal        uint64
}

type middleEndPressureState struct {
	value int
	stage int
}

type middleEndFrontendStatsProvider interface {
	MiddleEndFrontendStats() gproxy.MiddleEndFrontendStats
}

func startMiddleEndMonitor(service *middleend.Service, frontend middleEndFrontendStatsProvider) *middleEndMonitor {
	if service == nil {
		return nil
	}
	monitor := &middleEndMonitor{
		service:  service,
		frontend: frontend,
		stop:     make(chan struct{}),
		pressure: make(map[string]middleEndPressureState),
	}
	monitor.workers.Go(monitor.run)
	return monitor
}

func (m *middleEndMonitor) Stop() {
	if m == nil {
		return
	}
	m.stopper.Do(func() { close(m.stop) })
	m.workers.Wait()
}

func (m *middleEndMonitor) run() {
	m.observe()
	ticker := time.NewTicker(middleEndMonitorInterval)
	defer ticker.Stop()
	for {
		select {
		case <-m.stop:
			return
		case <-m.service.Done():
			return
		case <-ticker.C:
			m.observe()
		}
	}
}

func (m *middleEndMonitor) observe() {
	snapshot := m.service.Snapshot()
	var frontend gproxy.MiddleEndFrontendStats
	if m.frontend != nil {
		frontend = m.frontend.MiddleEndFrontendStats()
	}
	responseBackpressure, controlBackpressure := middleEndBackpressureTotals(snapshot.Supervisor)
	current := middleEndMonitorCounters{
		initialized:                 true,
		admitting:                   snapshot.Supervisor.Admitting,
		repairing:                   snapshot.Supervisor.Repairing,
		refreshFailures:             snapshot.Coordinator.RefreshFailures,
		generationFailures:          snapshot.Coordinator.GenerationFailures,
		natIPv4Successes:            snapshot.NAT.IPv4.Successes,
		natIPv4Failures:             snapshot.NAT.IPv4.Failures,
		natIPv6Successes:            snapshot.NAT.IPv6.Successes,
		natIPv6Failures:             snapshot.NAT.IPv6.Failures,
		slotFailures:                snapshot.Supervisor.SlotFailures,
		slotFailureAffectedBindings: snapshot.Supervisor.SlotFailureAffectedBindings,
		slotRepairSuccesses:         snapshot.Supervisor.SlotRepairSuccesses,
		slotRepairFailures:          snapshot.Supervisor.SlotRepairFailures,
		responseBackpressure:        responseBackpressure,
		controlBackpressure:         controlBackpressure,
		frontendInputPressure:       frontend.InputBackpressureEvents,
		frontendOutputPressure:      frontend.OutputBackpressureEvents,
		frontendOutputEvictions:     frontend.OutputEvictions,
		middleEndBindingsTotal:      frontend.MiddleEndBindingsTotal,
		directFallbacksActive:       frontend.DirectFallbacksActive,
		directFallbacksTotal:        frontend.DirectFallbacksTotal,
	}
	previous := m.previous
	if !previous.initialized && snapshot.NAT.Static {
		logMiddleEndStaticNAT("ipv4", snapshot.NAT.IPv4)
		logMiddleEndStaticNAT("ipv6", snapshot.NAT.IPv6)
	}
	logMiddleEndNATProbeChanges(
		"ipv4",
		snapshot.NAT.IPv4,
		previous.natIPv4Successes,
		previous.natIPv4Failures,
	)
	logMiddleEndNATProbeChanges(
		"ipv6",
		snapshot.NAT.IPv6,
		previous.natIPv6Successes,
		previous.natIPv6Failures,
	)
	if !previous.initialized || current.admitting != previous.admitting {
		if current.admitting {
			livePayloadCapacity, rotationPayloadCapacity := middleEndPayloadCapacity(snapshot, frontend)
			log.Info().
				Int("active_links", middleEndManagerLinks(snapshot.Supervisor.Active)).
				Int64("active_middleend_bindings", frontend.MiddleEndBindingsActive).
				Int64("active_direct_fallbacks", frontend.DirectFallbacksActive).
				Int64("live_payload_capacity_bytes", livePayloadCapacity).
				Int64("rotation_payload_capacity_bytes", rotationPayloadCapacity).
				Msg("Middle-End active generation ready; new clients use gnet ME links")
		} else if previous.initialized {
			log.Warn().Msg("Middle-End admission unavailable; new clients use direct fallback")
		}
	}
	if newFallbacks := middleEndCounterIncrease(current.directFallbacksTotal, previous.directFallbacksTotal); newFallbacks > 0 {
		log.Warn().
			Uint64("new_direct_fallbacks", newFallbacks).
			Int64("active_direct_fallbacks", frontend.DirectFallbacksActive).
			Uint64("direct_fallbacks_total", frontend.DirectFallbacksTotal).
			Msg("Middle-End client sessions committed to direct fallback; they remain direct until clients reconnect")
	}
	if current.directFallbacksActive == 0 && previous.directFallbacksActive > 0 {
		log.Info().Msg("Middle-End direct fallback sessions cleared")
	}
	if current.middleEndBindingsTotal > previous.middleEndBindingsTotal {
		log.Info().
			Uint64("new_middleend_sessions", current.middleEndBindingsTotal-previous.middleEndBindingsTotal).
			Uint64("middleend_sessions_total", current.middleEndBindingsTotal).
			Int64("active_middleend_bindings", frontend.MiddleEndBindingsActive).
			Msg("Middle-End client sessions committed to gnet ME links")
	}
	if !previous.initialized || current.repairing != previous.repairing {
		if current.repairing {
			log.Warn().Err(snapshot.Supervisor.LastError).Msg("Middle-End generation repair started")
		} else if previous.initialized {
			log.Info().Msg("Middle-End generation repair finished")
		}
	}
	if current.refreshFailures > previous.refreshFailures {
		log.Warn().
			Uint64("new_failures", current.refreshFailures-previous.refreshFailures).
			Err(snapshot.Coordinator.LastError).
			Msg("Middle-End artifact refresh failed; last-known-good or direct fallback remains active")
	}
	if current.generationFailures > previous.generationFailures {
		newFailures := current.generationFailures - previous.generationFailures
		if middleEndGenerationFailureRecovered(snapshot) {
			log.Info().
				Uint64("new_failures", newFailures).
				Err(snapshot.Coordinator.LastError).
				Msg("Middle-End recovered from transient generation build or apply failure")
		} else {
			log.Warn().
				Uint64("new_failures", newFailures).
				Err(snapshot.Coordinator.LastError).
				Msg("Middle-End generation build or apply failed; repair will retry")
		}
	}
	if current.slotRepairFailures > previous.slotRepairFailures {
		log.Warn().
			Uint64("new_failures", current.slotRepairFailures-previous.slotRepairFailures).
			Uint64("failures_total", current.slotRepairFailures).
			Int("repairing_slots", middleEndRepairingSlots(snapshot.Supervisor)).
			Err(snapshot.Supervisor.LastError).
			Msg("Middle-End physical-link replacement failed; recovery will retry while unaffected DC pools remain available")
	}
	if current.slotFailures > previous.slotFailures {
		failure := snapshot.Supervisor.LastSlotFailure
		affectedBindings := middleEndCounterIncrease(
			current.slotFailureAffectedBindings,
			previous.slotFailureAffectedBindings,
		)
		event := log.Debug()
		message := "Middle-End physical links closed; replacement started"
		if middleEndSlotFailureHasClientImpact(affectedBindings) {
			event = log.Warn()
			message = "Middle-End physical links failed; affected client bindings closed before replacement"
		}
		event.
			Uint64("new_failures", current.slotFailures-previous.slotFailures).
			Uint64("failures_total", current.slotFailures).
			Uint64("affected_bindings", affectedBindings).
			Uint64("affected_bindings_total", current.slotFailureAffectedBindings).
			Int("last_dc", int(failure.DCID)).
			Str("last_reason", string(failure.Reason)).
			Err(failure.Error).
			Msg(message)
	}
	if current.slotRepairSuccesses > previous.slotRepairSuccesses {
		log.Debug().
			Uint64("new_repairs", current.slotRepairSuccesses-previous.slotRepairSuccesses).
			Uint64("repairs_total", current.slotRepairSuccesses).
			Msg("Middle-End physical-link replacement finished")
	}
	if current.responseBackpressure > previous.responseBackpressure {
		log.Warn().
			Uint64("new_evictions", current.responseBackpressure-previous.responseBackpressure).
			Msg("Middle-End response pressure evicted buffered client bindings; shared links remain active")
	}
	if current.controlBackpressure > previous.controlBackpressure {
		log.Warn().
			Uint64("new_drops", current.controlBackpressure-previous.controlBackpressure).
			Msg("Middle-End best-effort close controls were dropped; liveness capacity stayed reserved")
	}
	if current.frontendInputPressure > previous.frontendInputPressure {
		log.Warn().
			Uint64("new_closes", current.frontendInputPressure-previous.frontendInputPressure).
			Msg("Middle-End aggregate client input pressure closed connections")
	}
	if current.frontendOutputPressure > previous.frontendOutputPressure {
		log.Warn().
			Uint64("new_rejections", current.frontendOutputPressure-previous.frontendOutputPressure).
			Msg("Middle-End aggregate client output pressure rejected response reservations")
	}
	if current.frontendOutputEvictions > previous.frontendOutputEvictions {
		log.Warn().
			Uint64("new_evictions", current.frontendOutputEvictions-previous.frontendOutputEvictions).
			Msg("Middle-End aggregate output pressure evicted the largest buffered clients")
	}
	m.observePressure("frontend", "input", "bytes", int(frontend.InputBytesHighWater), int(frontend.InputBytesLimit))
	m.observePressure("frontend", "output", "bytes", int(frontend.OutputBytesHighWater), int(frontend.OutputBytesLimit))
	m.observeManagerPressure("active", snapshot.Supervisor.Active, snapshot.Capacity)
	m.observeManagerPressure("retiring", snapshot.Supervisor.Retiring, snapshot.Capacity)
	m.observeLinkPressure("active", snapshot.Supervisor.Active, snapshot.Capacity)
	m.observeLinkPressure("retiring", snapshot.Supervisor.Retiring, snapshot.Capacity)
	m.previous = current
}

func middleEndCounterIncrease(current, previous uint64) uint64 {
	if current <= previous {
		return 0
	}
	return current - previous
}

func middleEndSlotFailureHasClientImpact(affectedBindings uint64) bool {
	return affectedBindings > 0
}

func middleEndGenerationFailureRecovered(snapshot middleend.ServiceSnapshot) bool {
	if !snapshot.Supervisor.Admitting {
		return false
	}
	coordinator := snapshot.Coordinator
	return (!coordinator.Applied && coordinator.Pending) || (coordinator.Applied && !coordinator.Pending)
}

func logMiddleEndStaticNAT(family string, snapshot middleend.NATResolverFamilySnapshot) {
	if !snapshot.Ready || !snapshot.PublicIP.IsValid() {
		return
	}
	log.Info().
		Str("family", family).
		Str("public_ip", snapshot.PublicIP.String()).
		Msg("Middle-End uses the configured NAT public IP for private direct sockets")
}

func logMiddleEndNATProbeChanges(
	family string,
	snapshot middleend.NATResolverFamilySnapshot,
	previousSuccesses uint64,
	previousFailures uint64,
) {
	if snapshot.Successes > previousSuccesses {
		log.Info().
			Str("family", family).
			Str("public_ip", snapshot.PublicIP.String()).
			Int("responding_servers", snapshot.RespondingServers).
			Int("agreeing_servers", snapshot.AgreeingServers).
			Uint64("successes_total", snapshot.Successes).
			Time("cache_expires_at", snapshot.ExpiresAt).
			Msg("Middle-End resolved the NAT public IP for private direct sockets")
	}
	if snapshot.Failures > previousFailures {
		log.Warn().
			Str("family", family).
			Uint64("new_failures", snapshot.Failures-previousFailures).
			Uint64("failures_total", snapshot.Failures).
			Time("retry_at", snapshot.RetryAt).
			Err(snapshot.LastFailure).
			Msg("Middle-End NAT public-IP discovery failed; direct fallback remains active")
	}
}

// middleEndPayloadCapacity returns conservative logical payload-retention
// ceilings. Queue budgets are independent, so each is counted once. Per-slot
// and per-binding manager limits are subsets of the manager-wide limits and
// are not counted again. Rotation permits at most two whole generations.
func middleEndPayloadCapacity(snapshot middleend.ServiceSnapshot, frontend gproxy.MiddleEndFrontendStats) (live, rotation int64) {
	frontendCapacity := frontend.InputBytesLimit + frontend.OutputBytesLimit
	capacity := snapshot.Capacity
	generationCapacity := func(manager *middleend.FixedBindingManagerSnapshot) int64 {
		if manager == nil {
			return 0
		}
		managerCapacity := int64(capacity.ManagerRequestBytes) +
			int64(capacity.ManagerControlBytes) +
			int64(capacity.ManagerResponseBytes)
		linkCapacity := int64(len(manager.Slots)) *
			(int64(capacity.LinkSubmissionBytes) + int64(capacity.LinkEventBytes))
		return managerCapacity + linkCapacity
	}

	activeCapacity := generationCapacity(snapshot.Supervisor.Active)
	retiringCapacity := generationCapacity(snapshot.Supervisor.Retiring)
	live = frontendCapacity + activeCapacity + retiringCapacity
	rotation = frontendCapacity + 2*max(activeCapacity, retiringCapacity)
	return live, rotation
}

func middleEndBackpressureTotals(snapshot middleend.GenerationSupervisorSnapshot) (response, control uint64) {
	for _, manager := range []*middleend.FixedBindingManagerSnapshot{snapshot.Active, snapshot.Retiring} {
		if manager == nil {
			continue
		}
		response += manager.ResponseBackpressureEvents
		control += manager.ControlBackpressureEvents
	}
	return response, control
}

func middleEndRepairingSlots(snapshot middleend.GenerationSupervisorSnapshot) int {
	total := 0
	for _, manager := range []*middleend.FixedBindingManagerSnapshot{snapshot.Active, snapshot.Retiring} {
		if manager != nil {
			total += manager.RepairingSlots
		}
	}
	return total
}

func middleEndManagerLinks(manager *middleend.FixedBindingManagerSnapshot) int {
	if manager == nil {
		return 0
	}
	return len(manager.Slots)
}

func (m *middleEndMonitor) observeManagerPressure(
	role string,
	manager *middleend.FixedBindingManagerSnapshot,
	capacity middleend.ServiceCapacitySnapshot,
) {
	if manager == nil {
		return
	}
	for _, queue := range []struct {
		name      string
		items     int
		itemLimit int
		bytes     int
		byteLimit int
	}{
		{name: "request", items: manager.RequestItemsHighWater, itemLimit: capacity.ManagerRequestItems, bytes: manager.RequestBytesHighWater, byteLimit: capacity.ManagerRequestBytes},
		{name: "control", items: manager.ControlItemsHighWater, itemLimit: capacity.ManagerControlItems, bytes: manager.ControlBytesHighWater, byteLimit: capacity.ManagerControlBytes},
		{name: "response", items: manager.ResponseItemsHighWater, itemLimit: capacity.ManagerResponseItems, bytes: manager.ResponseBytesHighWater, byteLimit: capacity.ManagerResponseBytes},
	} {
		m.observePressure(role, queue.name, "items", queue.items, queue.itemLimit)
		m.observePressure(role, queue.name, "bytes", queue.bytes, queue.byteLimit)
	}
}

func (m *middleEndMonitor) observeLinkPressure(
	role string,
	manager *middleend.FixedBindingManagerSnapshot,
	capacity middleend.ServiceCapacitySnapshot,
) {
	if manager == nil {
		return
	}
	linksByDC := make(map[middleend.DCID]int)
	for _, slot := range manager.Slots {
		linksByDC[slot.DCID]++
		identity := role + "/dc=" + strconv.Itoa(int(slot.DCID)) + "/link=" + strconv.Itoa(linksByDC[slot.DCID])
		for _, queue := range []struct {
			name      string
			items     int
			itemLimit int
			bytes     int
			byteLimit int
		}{
			{name: "submission", items: slot.Link.SubmissionHighWater, itemLimit: capacity.LinkSubmissionItems, bytes: slot.Link.SubmissionBytesHighWater, byteLimit: capacity.LinkSubmissionBytes},
			{name: "event", items: slot.Link.EventHighWater, itemLimit: capacity.LinkEventItems, bytes: slot.Link.EventBytesHighWater, byteLimit: capacity.LinkEventBytes},
		} {
			m.observePressure(identity, queue.name, "items", queue.items, queue.itemLimit)
			m.observePressure(identity, queue.name, "bytes", queue.bytes, queue.byteLimit)
		}
	}
}

func (m *middleEndMonitor) observePressure(role, queue, dimension string, value, limit int) {
	if limit <= 0 {
		return
	}
	key := role + "/" + queue + "/" + dimension
	previous := m.pressure[key]
	if value < previous.value {
		previous.stage = 0
	}
	percentage := value * 100 / limit
	stage := 0
	switch {
	case percentage >= 100:
		stage = 3
	case percentage >= 95:
		stage = 2
	case percentage >= 80:
		stage = 1
	}
	if stage > previous.stage {
		log.Warn().
			Str("generation", role).
			Str("queue", queue).
			Str("dimension", dimension).
			Int("high_water", value).
			Int("limit", limit).
			Int("percent", percentage).
			Msg("Middle-End queue high-water threshold crossed")
	}
	m.pressure[key] = middleEndPressureState{value: value, stage: stage}
}
