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

	"github.com/openshift-eng/openshift-tests-extension/pkg/cmd"
	"github.com/openshift-eng/openshift-tests-extension/pkg/extension"
	"github.com/openshift-eng/openshift-tests-extension/pkg/extension/extensiontests"
	"github.com/openshift-eng/openshift-tests-extension/pkg/ginkgo"
	"github.com/spf13/cobra"

	e2e "github.com/openshift/cluster-machine-approver/e2e"
)

func main() {
	registry := extension.NewRegistry()
	ext := extension.NewExtension("openshift", "payload", "cluster-machine-approver")

	// This explicitly discovers the Ginkgo specs in the e2e package and adapts
	// them for openshift-tests; it is separate from the TestE2E Go test entrypoint.
	specs, err := ginkgo.BuildExtensionTestSpecsFromOpenShiftGinkgoSuite()
	if err != nil {
		panic(fmt.Sprintf("couldn't build extension test specs from ginkgo: %v", err))
	}
	specs.AddBeforeAll(func() {
		e2e.InitCommonVariables()
	})

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
