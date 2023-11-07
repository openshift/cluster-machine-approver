package metrics

import (
	"sync/atomic"

	"github.com/openshift/cluster-machine-approver/pkg/controller"
	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/klog/v2"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

// defaultMetricsPort is the default port to expose metrics.
const DefaultMetricsPort = ":9191"

var (
	// CurrentPendingCSRCountDesc is a metric to report count of the pending csr in the cluster
	CurrentPendingCSRCountDesc = prometheus.NewDesc("mapi_current_pending_csr", "Count of pending CSRs at the cluster level", nil, nil)
	// CurrentPendingCSRCountDesc is a metric to report count of the pending csr in the cluster
	CurrentPendingNodeCSRCountDesc = prometheus.NewDesc("mapi_current_pending_node_csr", "Count of pending node CSRs at the cluster level", nil, nil)
	// MaxPendingCSRDesc is a metric to report threshold value of the pending csr beyond which csr will be ignored
	MaxPendingCSRDesc = prometheus.NewDesc("mapi_max_pending_csr", "Threshold value of the pending CSRs beyond which any new CSR requests will be ignored ", nil, nil)
)

func init() {
	metrics.Registry.MustRegister(&MetricsCollector{})
}

// MetricsCollector is implementing prometheus.Collector interface.
type MetricsCollector struct{}

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
	ch <- prometheus.MustNewConstMetric(CurrentPendingCSRCountDesc, prometheus.GaugeValue, float64(atomic.LoadUint32(&controller.PendingCSRs)))
	ch <- prometheus.MustNewConstMetric(CurrentPendingNodeCSRCountDesc, prometheus.GaugeValue, float64(atomic.LoadUint32(&controller.PendingNodeCSRs)))
	ch <- prometheus.MustNewConstMetric(MaxPendingCSRDesc, prometheus.GaugeValue, float64(atomic.LoadUint32(&controller.MaxPendingCSRs)))
	klog.V(4).Infof("collectMetrics exit")
}
