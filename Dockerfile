FROM registry.ci.openshift.org/openshift/release:golang-1.25 AS builder
WORKDIR /go/src/github.com/openshift/cluster-machine-approver
COPY . .
RUN make build && gzip bin/cluster-machine-approver-ext

FROM registry.ci.openshift.org/openshift/origin-v4.0:base
COPY --from=builder /go/src/github.com/openshift/cluster-machine-approver/machine-approver /usr/bin/
COPY --from=builder /go/src/github.com/openshift/cluster-machine-approver/bin/cluster-machine-approver-ext.gz /usr/bin/
COPY manifests /manifests
ENTRYPOINT ["/usr/bin/machine-approver"]
LABEL io.k8s.display-name="OpenShift Cluster Machine Approver" \
      io.k8s.description="This is an OpenShift component for managing machine approval" \
      com.redhat.component="cluster-machine-approver" \
      maintainer="OpenShift Auth Team <aos-auth-team@redhat.com>" \
      name="openshift/ose-cluster-machine-approver" \
      version="v4.0.0" \
      io.openshift.release.operator=true \
      io.openshift.tags="openshift,tests,e2e,e2e-extension"
