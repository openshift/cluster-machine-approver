package operator

import (
	"github.com/spf13/cobra"

	"github.com/openshift/cluster-machine-approver/pkg/operator"
	"github.com/openshift/cluster-machine-approver/pkg/version"
	"github.com/openshift/library-go/pkg/controller/controllercmd"
)

const (
	componentName      = "cluster-machine-approver"
	componentNamespace = "openshift-cluster-machine-approver"
)

func NewOperator() *cobra.Command {
	cmd := controllercmd.NewControllerCommandConfig(componentName, version.Get(), operator.RunOperator).NewCommand()
	cmd.Use = "operator"
	cmd.Short = "Start the machine approver operator"
	return cmd
}
