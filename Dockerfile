FROM registry.svc.ci.openshift.org/openshift/release:golang-1.10 AS builder
COPY . /go/src/github.com/openshift/cluster-machine-appover
RUN cd /go/src/github.com/openshift/cluster-machine-appover && go build -o machine-approver .

FROM registry.svc.ci.openshift.org/openshift/origin-v4.0:base
COPY --from=builder /go/src/github.com/openshift/cluster-machine-appover/machine-approver /usr/bin/machine-approver
COPY manifests /manifests
LABEL io.openshift.release.operator true
