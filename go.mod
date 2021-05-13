module github.com/openshift/cluster-machine-approver

go 1.15

require (
	github.com/onsi/ginkgo v1.15.0
	github.com/onsi/gomega v1.10.5
	github.com/openshift/api v0.0.0-20210415150416-88a128ebb551
	github.com/openshift/client-go v0.0.0-20210409155308-a8e62c60e930
	github.com/openshift/cluster-api v0.0.0-20191129101638-b09907ac6668
	github.com/openshift/library-go v0.0.0-20210414082648-6e767630a0dc
	github.com/prometheus/client_golang v1.9.0
	k8s.io/api v0.21.0
	k8s.io/apimachinery v0.21.0
	k8s.io/client-go v11.0.1-0.20190409021438-1a26190bd76a+incompatible
	k8s.io/klog/v2 v2.8.0
	sigs.k8s.io/controller-runtime v0.9.0-beta.1.0.20210512131817-ce2f0c92d77e
)

replace k8s.io/client-go => k8s.io/client-go v0.21.0
