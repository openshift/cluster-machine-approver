module github.com/openshift/cluster-machine-approver

go 1.15

require (
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/onsi/ginkgo v1.15.0
	github.com/onsi/gomega v1.10.5
	github.com/openshift/api v0.0.0-20210211120836-503a3dbce2c8
	github.com/openshift/client-go v0.0.0-20210112165513-ebc401615f47
	github.com/openshift/cluster-api v0.0.0-20191129101638-b09907ac6668
	github.com/openshift/library-go v0.0.0-20210205203934-9eb0d970f2f4
	github.com/prometheus/client_golang v1.7.1
	k8s.io/api v0.20.2
	k8s.io/apimachinery v0.20.2
	k8s.io/client-go v11.0.1-0.20190409021438-1a26190bd76a+incompatible
	k8s.io/klog/v2 v2.5.0
	sigs.k8s.io/controller-runtime v0.8.2
)

replace k8s.io/client-go => k8s.io/client-go v0.20.0
