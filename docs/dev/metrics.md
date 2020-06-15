# CMA Metrics

The Cluster Machine Approver reports the following metrics:

## Metrics about pending certificate signing requests (CSRs)

These metrics show how many CSRs are currently pending as well as the
maximum number allowed to be pending. These can be useful to help diagnose
the flow of new Nodes being added to the cluster.

```
# HELP mapi_current_pending_csr Count of pending CSRs at the cluster level
# TYPE mapi_current_pending_csr gauge
mapi_current_pending_csr 0
# HELP mapi_max_pending_csr Threshold value of the pending CSRs beyond which any new CSR requests will be ignored 
# TYPE mapi_max_pending_csr gauge
mapi_max_pending_csr 108
```

## Metrics about the Prometheus collectors

Prometheus provides some default metrics about the internal state
of the running process and the metric collection. You can find more information
about these metric names and their labels through the following links:

* [Prometheus documentation, Standard and runtime collectors](https://prometheus.io/docs/instrumenting/writing_clientlibs/#standard-and-runtime-collectors)
* [Prometheus client Go language collectors](https://github.com/prometheus/client_golang/blob/master/prometheus/go_collector.go)
* [Prometheus client HTTP collectors](https://github.com/prometheus/client_golang/blob/master/prometheus/promhttp/http.go)
