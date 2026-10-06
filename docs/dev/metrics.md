# CMA Metrics

The Cluster Machine Approver reports the following metrics:

## Metrics about pending certificate signing requests (CSRs)

These metrics show how many recently pending node CSRs are currently counted
as well as the threshold used by MachineApproverMaxPendingCSRsReached.
They help diagnose Node bootstrap and CSR approval behavior during scale-up.

```text
# HELP mapi_current_pending_csr Count of recently pending node CSRs at the cluster level
# TYPE mapi_current_pending_csr gauge
mapi_current_pending_csr 0
# HELP mapi_max_pending_csr Recently pending node CSR count threshold used by MachineApproverMaxPendingCSRsReached
# TYPE mapi_max_pending_csr gauge
mapi_max_pending_csr 108
# HELP mapi_duplicate_csr_denied_total Count of pending node CSRs denied because a newer CSR exists for the same node and signer
# TYPE mapi_duplicate_csr_denied_total counter
mapi_duplicate_csr_denied_total 0
```

`MachineApproverMaxPendingCSRsReached` fires when
`mapi_current_pending_csr > mapi_max_pending_csr` for 5m.
`MachineApproverDuplicateCSRDenied` fires when
`increase(mapi_duplicate_csr_denied_total[5m]) > 0` for 15m
(sustained prune pressure; brief one-off denials do not alert).

## Metrics about the Prometheus collectors

Prometheus provides some default metrics about the internal state
of the running process and the metric collection. You can find more information
about these metric names and their labels through the following links:

* [Prometheus documentation, Standard and runtime collectors](https://prometheus.io/docs/instrumenting/writing_clientlibs/#standard-and-runtime-collectors)
* [Prometheus client Go language collectors](https://github.com/prometheus/client_golang/blob/master/prometheus/go_collector.go)
* [Prometheus client HTTP collectors](https://github.com/prometheus/client_golang/blob/master/prometheus/promhttp/http.go)
