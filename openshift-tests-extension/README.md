# OpenShift Tests Extension (OTE)

This directory is a separate Go module for the
`cluster-machine-approver-tests-ext` binary. The binary is embedded in the
operator image as `/usr/bin/cluster-machine-approver-tests-ext.gz` for
`openshift-tests` to discover and run the component's e2e tests.

The extension's `cmd/main.go` explicitly calls
`BuildExtensionTestSpecsFromOpenShiftGinkgoSuite` to discover Ginkgo specs in
`e2e`. This is separate from `e2e/e2e_suite_test.go`, which provides the
ordinary `go test` entrypoint for that suite. Put future OTE-discoverable
Ginkgo specs in regular `.go` files; Go's `_test.go` files are only compiled
for the normal Go test entrypoint and are not visible to the extension binary.

The extension module replaces upstream Ginkgo with the OpenShift Ginkgo fork,
which provides the compatibility expected by the OTE adapter. Ginkgo labels
`platform:<name>` and `skip-topology:<mode>` are translated to OTE include and
exclude selectors in `cmd/main.go`.

Build and list discovered tests locally:

```sh
make cluster-machine-approver-tests-ext
./bin/cluster-machine-approver-tests-ext list tests
./bin/cluster-machine-approver-tests-ext list suites
```