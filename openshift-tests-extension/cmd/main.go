// Copyright 2026 Red Hat, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/openshift-eng/openshift-tests-extension/pkg/cmd"
	"github.com/openshift-eng/openshift-tests-extension/pkg/extension"
	"github.com/openshift-eng/openshift-tests-extension/pkg/extension/extensiontests"
	"github.com/openshift-eng/openshift-tests-extension/pkg/ginkgo"
	"github.com/spf13/cobra"

	_ "github.com/openshift/cluster-machine-approver/e2e"
)

func main() {
	registry := extension.NewRegistry()
	ext := extension.NewExtension("openshift", "payload", "cluster-machine-approver")

	serialTimeout := 2 * time.Minute
	ext.AddSuite(extension.Suite{
		Name:        "cluster-machine-approver/serial",
		Description: "Serial cluster-machine-approver tests that complete within minutes.",
		Parents:     []string{"openshift/conformance/serial"},
		Qualifiers:  []string{`labels.exists(l, l == "Serial")`},
		Parallelism: 1,
		TestTimeout: &serialTimeout,
	})

	// The extension module vendors the local e2e package, so ModuleTestsOnly
	// would incorrectly filter out these component-owned specs as vendored.
	// This package imports no external Ginkgo specs, so including vendored specs
	// here selects the local e2e suite.
	specs, err := ginkgo.BuildExtensionTestSpecsFromOpenShiftGinkgoSuite(extensiontests.AllTestsIncludingVendored())
	if err != nil {
		panic(fmt.Sprintf("couldn't build extension test specs from ginkgo: %v", err))
	}
	// Translate selected Ginkgo labels into OTE environment selectors.
	specs.Walk(func(spec *extensiontests.ExtensionTestSpec) {
		for label := range spec.Labels {
			if platform, ok := strings.CutPrefix(label, "platform:"); ok {
				spec.Include(extensiontests.PlatformEquals(platform))
			}
			if topology, ok := strings.CutPrefix(label, "skip-topology:"); ok {
				spec.Exclude(extensiontests.TopologyEquals(topology))
			}
		}
	})

	ext.AddSpecs(specs)
	registry.Register(ext)

	root := &cobra.Command{Long: "cluster-machine-approver tests extension for OpenShift"}
	root.AddCommand(cmd.DefaultExtensionCommands(registry)...)
	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}
