package metrics

import (
	"net/http"
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Collector collects relay metrics
type Collector struct {
	connections    atomic.Int64
	circuits       atomic.Int64
	bytesReceived  atomic.Uint64
	bytesSent      atomic.Uint64

	// Prometheus metrics
	connectionsGauge prometheus.Gauge
	circuitsGauge    prometheus.Gauge
	bytesReceivedCounter prometheus.Counter
	bytesSentCounter     prometheus.Counter
	circuitsCreatedCounter prometheus.Counter
	requestLatency   prometheus.Histogram
}

// NewCollector creates a new metrics collector
func NewCollector() *Collector {
	c := &Collector{
		connectionsGauge: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "tonnet_relay_connections_active",
			Help: "Number of active peer connections",
		}),
		circuitsGauge: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "tonnet_relay_circuits_active",
			Help: "Number of active circuits",
		}),
		bytesReceivedCounter: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "tonnet_relay_bytes_received_total",
			Help: "Total bytes received",
		}),
		bytesSentCounter: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "tonnet_relay_bytes_sent_total",
			Help: "Total bytes sent",
		}),
		circuitsCreatedCounter: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "tonnet_relay_circuits_created_total",
			Help: "Total circuits created",
		}),
		requestLatency: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "tonnet_relay_request_latency_seconds",
			Help:    "Request latency distribution",
			Buckets: prometheus.DefBuckets,
		}),
	}

	prometheus.MustRegister(
		c.connectionsGauge,
		c.circuitsGauge,
		c.bytesReceivedCounter,
		c.bytesSentCounter,
		c.circuitsCreatedCounter,
		c.requestLatency,
	)

	return c
}

// IncrConnections increments the connection count
func (c *Collector) IncrConnections() {
	c.connections.Add(1)
	c.connectionsGauge.Inc()
}

// DecrConnections decrements the connection count
func (c *Collector) DecrConnections() {
	c.connections.Add(-1)
	c.connectionsGauge.Dec()
}

// GetConnections returns the current connection count
func (c *Collector) GetConnections() int64 {
	return c.connections.Load()
}

// IncrCircuits increments the circuit count
func (c *Collector) IncrCircuits() {
	c.circuits.Add(1)
	c.circuitsGauge.Inc()
	c.circuitsCreatedCounter.Inc()
}

// DecrCircuits decrements the circuit count
func (c *Collector) DecrCircuits() {
	c.circuits.Add(-1)
	c.circuitsGauge.Dec()
}

// GetCircuits returns the current circuit count
func (c *Collector) GetCircuits() int64 {
	return c.circuits.Load()
}

// AddBytesReceived adds to the bytes received counter
func (c *Collector) AddBytesReceived(n uint64) {
	c.bytesReceived.Add(n)
	c.bytesReceivedCounter.Add(float64(n))
}

// GetBytesReceived returns total bytes received
func (c *Collector) GetBytesReceived() uint64 {
	return c.bytesReceived.Load()
}

// AddBytesSent adds to the bytes sent counter
func (c *Collector) AddBytesSent(n uint64) {
	c.bytesSent.Add(n)
	c.bytesSentCounter.Add(float64(n))
}

// GetBytesSent returns total bytes sent
func (c *Collector) GetBytesSent() uint64 {
	return c.bytesSent.Load()
}

// ObserveLatency records a request latency
func (c *Collector) ObserveLatency(seconds float64) {
	c.requestLatency.Observe(seconds)
}

// Handler returns the Prometheus HTTP handler
func (c *Collector) Handler() http.Handler {
	return promhttp.Handler()
}

// Stats returns current statistics
func (c *Collector) Stats() Stats {
	return Stats{
		Connections:   c.connections.Load(),
		Circuits:      c.circuits.Load(),
		BytesReceived: c.bytesReceived.Load(),
		BytesSent:     c.bytesSent.Load(),
	}
}

// Stats holds current statistics
type Stats struct {
	Connections   int64
	Circuits      int64
	BytesReceived uint64
	BytesSent     uint64
}
