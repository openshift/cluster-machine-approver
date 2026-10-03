package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/openshift-eng/openshift-tests-extension/pkg/cmd"
	e "github.com/openshift-eng/openshift-tests-extension/pkg/extension"
	et "github.com/openshift-eng/openshift-tests-extension/pkg/extension/extensiontests"
	g "github.com/openshift-eng/openshift-tests-extension/pkg/ginkgo"
	"github.com/spf13/cobra"

	_ "github.com/openshift/cluster-machine-approver/openshift-tests-extension/test/e2e"
)

func main() {
	extensionRegistry := e.NewRegistry()
	machineApproverExtension := e.NewExtension("openshift", "payload", "cluster-machine-approver")

	// Define test suites
	machineApproverExtension.AddSuite(e.Suite{
		Name: "machine-approver/conformance/parallel",
		Parents: []string{
			"openshift/conformance/parallel",
		},
		Qualifiers: []string{`!labels.exists(l, l == "Serial") && labels.exists(l, l == "Conformance")`},
	})

	machineApproverExtension.AddSuite(e.Suite{
		Name: "machine-approver/conformance/serial",
		Parents: []string{
			"openshift/conformance/serial",
		},
		Qualifiers: []string{`labels.exists(l, l == "Serial") && labels.exists(l, l == "Conformance")`},
	})

	machineApproverExtension.AddSuite(e.Suite{
		Name:       "machine-approver/e2e",
		Qualifiers: []string{`name.contains("[Feature:MachineApprover]")`},
	})

	// Build extension test specs from Ginkgo suite
	specs, err := g.BuildExtensionTestSpecsFromOpenShiftGinkgoSuite()
	if err != nil {
		panic(fmt.Sprintf("couldn't build extension test specs from ginkgo: %+v", err.Error()))
	}

	// Apply platform label filters
	applyLabelFilters(specs)

	machineApproverExtension.AddSpecs(specs)
	extensionRegistry.Register(machineApproverExtension)

	root := &cobra.Command{
		Long: "Cluster Machine Approver tests extension for OpenShift",
	}

	root.AddCommand(cmd.DefaultExtensionCommands(extensionRegistry)...)

	if err := func() error {
		return root.Execute()
	}(); err != nil {
		os.Exit(1)
	}
}

func applyLabelFilters(specs et.ExtensionTestSpecs) {
	// Apply Platform label filters: tests with Platform:platformname only run on that platform
	specs.Walk(func(spec *et.ExtensionTestSpec) {
		for label := range spec.Labels {
			if strings.HasPrefix(label, "Platform:") {
				platformName := strings.TrimPrefix(label, "Platform:")
				spec.Include(et.PlatformEquals(platformName))
			}
		}
	})

	// Apply NoPlatform label filters: tests with NoPlatform:platformname excluded from that platform
	specs.Walk(func(spec *et.ExtensionTestSpec) {
		for label := range spec.Labels {
			if strings.HasPrefix(label, "NoPlatform:") {
				platformName := strings.TrimPrefix(label, "NoPlatform:")
				spec.Exclude(et.PlatformEquals(platformName))
			}
		}
	})
}
