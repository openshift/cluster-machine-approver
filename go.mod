module github.com/openshift/cluster-machine-approver

go 1.13

require (
	github.com/go-logr/zapr v0.1.1 // indirect
	github.com/golang/groupcache v0.0.0-20200121045136-8c9f03a8e57e // indirect
	github.com/google/go-cmp v0.3.1 // indirect
	github.com/googleapis/gnostic v0.3.1 // indirect
	github.com/hashicorp/golang-lru v0.5.3 // indirect
	github.com/imdario/mergo v0.3.8 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.2-0.20181231171920-c182affec369 // indirect
	github.com/onsi/ginkgo v1.12.0 // indirect
	github.com/onsi/gomega v1.9.0 // indirect
	github.com/openshift/cluster-api v0.0.0-20191129101638-b09907ac6668
	github.com/pkg/errors v0.8.2-0.20190227000051-27936f6d90f9 // indirect
	github.com/prometheus/client_golang v1.1.0
	github.com/prometheus/common v0.7.0 // indirect
	github.com/prometheus/procfs v0.0.5 // indirect
	go.uber.org/zap v1.14.1 // indirect
	golang.org/x/net v0.0.0-20200202094626-16171245cfb2 // indirect
	golang.org/x/oauth2 v0.0.0-20190604053449-0f29369cfe45 // indirect
	golang.org/x/time v0.0.0-20190921001708-c4c64cad1fd0 // indirect
	golang.org/x/tools v0.0.0-20200115044656-831fdb1e1868 // indirect
	google.golang.org/appengine v1.6.4 // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	k8s.io/api v0.18.5
	k8s.io/apiextensions-apiserver v0.18.5 // indirect
	k8s.io/apimachinery v0.18.5
	k8s.io/client-go v11.0.1-0.20190409021438-1a26190bd76a+incompatible
	k8s.io/klog v1.0.0
	sigs.k8s.io/controller-runtime v0.6.0 // indirect
	sigs.k8s.io/testing_frameworks v0.1.2 // indirect
)

replace k8s.io/client-go => k8s.io/client-go v11.0.0+incompatible

replace k8s.io/api => k8s.io/api v0.0.0-20190313235455-40a48860b5ab

replace k8s.io/apimachinery => k8s.io/apimachinery v0.0.0-20190313205120-d7deff9243b1

replace github.com/openshift/cluster-api => github.com/openshift/cluster-api v0.0.0-20190503193905-cad0f8326cd2

replace github.com/prometheus/client_golang => github.com/prometheus/client_golang v0.9.4

replace sigs.k8s.io/controller-runtime => sigs.k8s.io/controller-runtime v0.1.1
