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

The serving-CSR worker and control-plane tests are serial. The extension
advertises them in `cluster-machine-approver/serial`, whose parent is the
`openshift/conformance/serial` suite.

Build and list discovered tests locally:

```sh
make cluster-machine-approver-tests-ext
./bin/cluster-machine-approver-tests-ext list tests --suite cluster-machine-approver/serial
./bin/cluster-machine-approver-tests-ext list suites
```