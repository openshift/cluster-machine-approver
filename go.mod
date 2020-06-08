module github.com/openshift/cluster-machine-approver

go 1.15

require (
	github.com/go-logr/logr v0.2.1 // indirect
	github.com/googleapis/gnostic v0.5.3 // indirect
	github.com/onsi/ginkgo v1.14.2
	github.com/onsi/gomega v1.10.3
	github.com/openshift/api v0.0.0-20201023182528-2ed1db6e1551
	github.com/openshift/cluster-api v0.0.0-20191129101638-b09907ac6668
	github.com/openshift/library-go v0.0.0-20201026125231-a28d3d1bad23
	github.com/prometheus/client_golang v1.8.0
	k8s.io/api v0.19.3
	k8s.io/apimachinery v0.19.3
	k8s.io/client-go v11.0.1-0.20190409021438-1a26190bd76a+incompatible
	k8s.io/klog/v2 v2.3.0
	sigs.k8s.io/controller-runtime v0.6.3
)

replace k8s.io/client-go => k8s.io/client-go v0.19.0
