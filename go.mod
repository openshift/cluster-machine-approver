module github.com/openshift/cluster-machine-approver

go 1.15

require (
	github.com/onsi/ginkgo v1.14.1
	github.com/onsi/gomega v1.10.2
	github.com/openshift/api v0.0.0-20210428205234-a8389931bee7
	github.com/openshift/client-go v0.0.0-20210112165513-ebc401615f47
	github.com/openshift/library-go v0.0.0-20210205203934-9eb0d970f2f4
	github.com/openshift/machine-api-operator v0.2.1-0.20210516083017-bb9e0b5c1170
	github.com/prometheus/client_golang v1.7.1
	k8s.io/api v0.20.6
	k8s.io/apimachinery v0.20.6
	k8s.io/client-go v0.20.6
	k8s.io/klog/v2 v2.4.0
	sigs.k8s.io/controller-runtime v0.7.0
)

replace sigs.k8s.io/cluster-api-provider-aws => github.com/openshift/cluster-api-provider-aws v0.2.1-0.20210430231032-3967c2861801

replace sigs.k8s.io/cluster-api-provider-azure => github.com/openshift/cluster-api-provider-azure v0.1.0-alpha.3.0.20210318155632-e744815d9f05
