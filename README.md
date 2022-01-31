# cluster-machine-approver

This controller provides the following functionality:
 - Watch the CSR endpoint for CSR requests
 - Decide if the CSR should be allowed or denied
 - Approve or deny and update CSR status

## Introduction

Kubernetes includes support for [TLS
bootstrapping](https://kubernetes.io/docs/reference/command-line-tools-reference/kubelet-tls-bootstrapping/)
for Nodes, which OpenShift makes use of.

Kubelet needs two certificates for its normal operation:

* **Client certificate** - for securely communicating with the Kubernetes API
  server
* **Server certificate** - for use in its own local https endpoint, [used by
  the API server to talk back to
  kubelet](https://kubernetes.io/docs/concepts/architecture/master-node-communication/#apiserver-to-kubelet)

When a new host is provisioned, kubelet will start and communicates to the CSR
(Certificate Signing Request) API endpoint to request signed client and server
certificates.  It issues this request using [bootstrap
credentials](https://kubernetes.io/docs/reference/command-line-tools-reference/kubelet-tls-bootstrapping/#initial-bootstrap-authentication)
that it finds on its local filesystem.

At this point, these CSRs must be approved.  They can be manually [approved
through the API using
kubectl](https://kubernetes.io/docs/reference/command-line-tools-reference/kubelet-tls-bootstrapping/#kubectl-approval),
or [kube-controller-manager can be configured to approve
them](https://kubernetes.io/docs/reference/command-line-tools-reference/kubelet-tls-bootstrapping/#kube-controller-manager-configuration).
Alternatively, some custom component could be built to approve CSRs through the
API, which is what OpenShift has done.

## OpenShift and CSRs

OpenShift includes a custom component to approve CSRs: the
`cluster-machine-approver`.  The `cluster-machine-approver` is used to
automatically approve CSRs, but with more strict criteria than what was
supported in `kube-controller-manager`.

Note that the `cluster-machine-approver` only kicks in post-install.  During
the cluster bootstrapping phase, the [approve-csr service on the bootstrap
node](https://github.com/openshift/installer/commit/c5d4d0f3ab3b0e65cb8d6af3ff6dfb3162dfa1d6)
automatically approves all CSRs.  This bootstrap service will end up approving
the CSRs for the control plane nodes, while `cluster-machine-approver` will
take over for future new CSRs from worker nodes.

### Understanding node join

The default OCP flow uses CoreOS (e.g. RHEL CoreOS), which is provisioned via
Ignition.  All the initial node configuration is rendered into Ignition
by the [MCO](https://github.com/openshift/machine-config-operator/).  Further,
before kubelet even starts, the OS is upgraded to the latest image.  For
more information on this, see:
https://github.com/openshift/machine-config-operator/blob/master/docs/OSUpgrades.md

And specifically for the initial kubelet config, see [cluster_server.go](https://github.com/openshift/machine-config-operator/blob/0476b259ab6895e7aaca237581bc19b4d4610e12/pkg/server/cluster_server.go#L58)
which is part of the "Machine Config Server" that provides Ignition
when the node requests it on the first boot.

### Disabling Node Client CSR Approvals

It is possible to disable node client CSR approvals completely.  This is done
using a `ConfigMap` resource, as shown in [this PR
comment](https://github.com/openshift/cluster-machine-approver/pull/26#issuecomment-492782189).

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: machine-approver-config
  namespace: openshift-cluster-machine-approver
data:
  config.yaml: |-
    nodeClientCert:
      disabled: true
```

This may be useful if you explicitly want to only allow manual CSR approvals
for new nodes.

### Node Client CSR Approval Workflow

CSR approval details can be found in [csr_check.go](https://github.com/openshift/cluster-machine-approver/blob/master/pkg/controller/csr_check.go).  Assuming
this has not been disabled, the following criteria must be met for the client
CSR to be approved:

* The user must be the node bootstrapper
  * The username in the CSR must be
    `system:serviceaccount:openshift-machine-config-operator:node-bootstrapper`
  * The groups in the CSR must be
    `system:serviceaccounts:openshift-machine-config-operator`,
    `system:serviceaccounts`, and `system:authenticated`.
* A `Node` object must not yet exist for the node that created the CSR.
* The `Machine` API is used to do a sanity check.  A `Machine` must exist with
  a `NodeInternalDNS` address in its `Status` that matches the future name of
  the `Node`, as found in the CSR.
* This `Machine` must not have a `NodeRef` set.
* The CSR creation timestamp must be close to the `Machine` creation timestamp
  (currently within 2 hours)
* The CSR is for node client auth.

### Node Server CSR Approval Workflow

Details of this workflow can be found in the same file as the client workflow,
[csr_check.go](https://github.com/openshift/cluster-machine-approver/blob/master/pkg/controller/csr_check.go).

For this workflow, it is assumed that the `Node` is now up and running, and the
`Node` object exists in the API.  Validation for the server CSR is different
than the client case and is based primarily on matching addresses between
associated `Node` and `Machine` objects.

First, there must be a `Machine` object with a `NodeRef` field set to the
`Node` that sent this CSR.  The `NodeRef` is set by a `Node` controller under
the [machine-api-operator](https://github.com/openshift/machine-api-operator).

Once a `Node`-`Machine` pair has been identified, validation is done on all of
the `Addresses` in the `Status` field of the `Machine`.  The CSR requests a
certificate with the [SAN (Subject Alternate Names)
extension](https://geekflare.com/san-ssl-certificate/).  The resulting
certificate will be valid for every address or hostname listed on the `Node`
resource to validate this request, the `cluster-machine-approver` ensures that
every DNS name or IP address in the CSR matches a (`NodeInternalDNS`,
`NodeExternalDNS`, `NodeHostName`) or (`NodeInternalIP`, `NodeExternalIP`)
address on the corresponding `Machine` object.

### Requirements for Cluster API Providers

As discussed in previous sections, `cluster-machine-approver` imposes some
requirements on each Cluster API provider used with the
[machine-api-operator](https://github.com/openshift/machine-api-operator).
This section serves as a summary of those requirements.

* A `Machine` must have a `NodeInternalDNS` set in `Status.Addresses` that
  matches the name of the `Node`.  The `NodeInternalDNS` entry **must** be
  present, even before the `Node` resource is created.
* A `Machine` must also have matching `NodeInternalDNS`, `NodeExternalDNS`,
  `NodeHostName`, `NodeInternalIP`, and `NodeExternalIP` addresses as those
  listed on the `Node` resource.  All of these addresses are placed in the CSR
  and are validated against the addresses on the `Machine` object.
