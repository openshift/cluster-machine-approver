package main

import (
	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog"
	"sync/atomic"
)

var (
	// CurrentPendingCSRCountDesc is a metric to report count of the pending csr in the cluster
	CurrentPendingCSRCountDesc = prometheus.NewDesc("mapi_current_pending_csr", "Count of pending CSRs at the cluster level", nil, nil)
	// MaxPendingCSRDesc is a metric to report threshold value of the pending csr beyond which csr will be ignored
	MaxPendingCSRDesc = prometheus.NewDesc("mapi_max_pending_csr", "Threshold value of the pending CSRs beyond which any new CSR requests will be ignored ", nil, nil)
)

// MetricsCollector is implementing prometheus.Collector interface.
type MetricsCollector struct {
	cacheIndexer cache.Indexer
}

func NewMetricsCollector(indexer cache.Indexer) *MetricsCollector {
	return &MetricsCollector{
		cacheIndexer: indexer,
	}
}

// Collect is method required to implement the prometheus.Collector(prometheus/client_golang/prometheus/collector.go) interface.
func (mc *MetricsCollector) Collect(ch chan<- prometheus.Metric) {
	mc.collectMetrics(ch)
}

// Describe implements the prometheus.Collector interface.
func (mc MetricsCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- CurrentPendingCSRCountDesc
	ch <- MaxPendingCSRDesc
}

// Collect implements the prometheus.Collector interface.
func (mc MetricsCollector) collectMetrics(ch chan<- prometheus.Metric) {
	pending := recentlyPendingCSRs(mc.cacheIndexer)
	ch <- prometheus.MustNewConstMetric(CurrentPendingCSRCountDesc, prometheus.GaugeValue, float64(pending))
	ch <- prometheus.MustNewConstMetric(MaxPendingCSRDesc, prometheus.GaugeValue, float64(atomic.LoadUint32(&maxPendingCSRs)))
	klog.V(4).Infof("collectMetrics exit")
}
