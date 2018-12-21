#
# The standard name for this image is openshift/origin-cluster-machine-approver
#
FROM openshift/origin-release:golang-1.10
COPY . /go/src/github.com/openshift/cluster-machine-approver
RUN cd /go/src/github.com/openshift/cluster-machine-approver && go build ./cmd/machine-approver

FROM centos:7
COPY --from=0 /go/src/github.com/openshift/cluster-machine-approver/machine-approver /usr/bin/machine-approver

COPY manifests /manifests
LABEL io.openshift.release.operator true
