# OpenShift Tests Extension (OTE)

This directory is a separate Go module for the
`cluster-machine-approver-tests-ext` binary. The binary is embedded in the
operator image as `/usr/bin/cluster-machine-approver-tests-ext.gz` for
`openshift-tests` to discover and run the component's e2e tests.

The extension's `cmd/main.go` explicitly calls
`BuildExtensionTestSpecsFromOpenShiftGinkgoSuite` to discover Ginkgo specs in
`e2e`. Put OTE-discoverable Ginkgo specs in regular `.go` files; Go's
`_test.go` files are not visible to the extension binary. The `go test` suite
entrypoint in `e2e/e2e_suite_test.go` is guarded by the `e2e` build tag so
ordinary unit-test runs do not execute live cluster disruptions; run that suite
explicitly with `go test -tags=e2e ./e2e` when a cluster is available.

The extension module replaces upstream Ginkgo with the OpenShift Ginkgo fork,
which provides the compatibility expected by the OTE adapter. Ginkgo labels
`platform:<name>` and `skip-topology:<mode>` are translated to OTE include and
exclude selectors in `cmd/main.go`.

The serving-CSR worker and control-plane tests run in parallel on disjoint Node
roles, including while other tests add or remove Nodes. The extension advertises
`cluster-machine-approver/parallel`, whose parent is
`openshift/conformance/parallel`. The child suite uses parallelism 2 and a
12-minute timeout; parent execution inherits the parent's scheduling and timeout.
Each test bounds its own work to 10 minutes, with a separate one-minute cleanup
allowance. It temporarily appends an unauthorized hostname without replacing any
real addresses. After a failed attempt it retries on another settled Node only
if the selected Node is no longer stable (gone, replaced, terminating or no
longer settled Ready). Failures on stable Nodes fail the test. Unsupported roles
and MicroShift are skipped.

Build and list discovered tests locally:

```sh
make cluster-machine-approver-tests-ext
./bin/cluster-machine-approver-tests-ext list tests --suite cluster-machine-approver/parallel
./bin/cluster-machine-approver-tests-ext list suites
```