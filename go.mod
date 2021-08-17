module github.com/openshift/cluster-machine-approver

go 1.16

require (
	github.com/onsi/ginkgo v1.16.4
	github.com/onsi/gomega v1.13.0
	github.com/openshift/api v0.0.0-20210816181336-8ff39b776da3
	github.com/openshift/client-go v0.0.0-20210730113412-1811c1b3fc0e
	github.com/openshift/library-go v0.0.0-20210811133500-5e31383de2a7
	github.com/openshift/machine-api-operator v0.2.1-0.20210810163111-abd3c0efdfee
	github.com/prometheus/client_golang v1.11.0
	k8s.io/api v0.22.0
	k8s.io/apimachinery v0.22.0
	k8s.io/client-go v0.22.0
	k8s.io/klog/v2 v2.9.0
	sigs.k8s.io/controller-runtime v0.9.3
)

replace (
	sigs.k8s.io/cluster-api-provider-aws => github.com/openshift/cluster-api-provider-aws v0.2.1-0.20210622023641-c69a3acaee27
	sigs.k8s.io/cluster-api-provider-azure => github.com/openshift/cluster-api-provider-azure v0.1.0-alpha.3.0.20210816141152-a7c40345b994
)
