module github.com/openshift/cluster-machine-approver

go 1.15

require (
	github.com/onsi/ginkgo v1.14.1
	github.com/onsi/gomega v1.10.2
	github.com/openshift/api v0.0.0-20201216151826-78a19e96f9eb
	github.com/openshift/client-go v0.0.0-20201214125552-e615e336eb49
	github.com/openshift/library-go v0.0.0-20201215165635-4ee79b1caed5
	github.com/openshift/machine-api-operator v0.2.1-0.20201216110516-d9e48bb9fc0b
	github.com/prometheus/client_golang v1.7.1
	k8s.io/api v0.20.0
	k8s.io/apimachinery v0.20.0
	k8s.io/client-go v0.20.0
	k8s.io/klog/v2 v2.4.0
	sigs.k8s.io/controller-runtime v0.7.0
)

replace sigs.k8s.io/cluster-api-provider-aws => github.com/openshift/cluster-api-provider-aws v0.2.1-0.20201216171336-0b00fb8d96ac

replace sigs.k8s.io/cluster-api-provider-azure => github.com/openshift/cluster-api-provider-azure v0.1.0-alpha.3.0.20201209184807-075372e2ed03
