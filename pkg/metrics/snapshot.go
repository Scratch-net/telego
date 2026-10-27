package metrics

import (
	"context"

	"go.opentelemetry.io/otel/metric"
)

// snapshotMetricGroup builds one collection callback for a stats source. Only
// instrument registrations are retained; each collection owns its snapshot.
type snapshotMetricGroup[T any] struct {
	meter        metric.Meter
	instruments  []metric.Observable
	observations []func(metric.Observer, T)
}

func (g *snapshotMetricGroup[T]) add(observe func(metric.Observer, T), instruments ...metric.Observable) {
	g.instruments = append(g.instruments, instruments...)
	g.observations = append(g.observations, observe)
}

func (g *snapshotMetricGroup[T]) register(source func() T) {
	g.meter.RegisterCallback(func(_ context.Context, observer metric.Observer) error {
		snapshot := source()
		for _, observe := range g.observations {
			observe(observer, snapshot)
		}
		return nil
	}, g.instruments...)
}
