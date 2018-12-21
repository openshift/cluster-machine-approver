package operator

import (
	"fmt"
	"time"

	"github.com/openshift/library-go/pkg/controller/controllercmd"

	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
)

func RunOperator(ctx *controllercmd.ControllerContext) error {
	kubeClient, err := kubernetes.NewForConfig(ctx.KubeConfig)
	if err != nil {
		return err
	}
	informer := informers.NewSharedInformerFactory(kubeClient, 10*time.Minute)

	approverController := NewMachineApproverController(
		informer.Certificates().V1beta1().CertificateSigningRequests(),
		kubeClient.CertificatesV1beta1(),
	)
	informer.Start(ctx.StopCh)
	go approverController.Run(1, ctx.StopCh)

	<-ctx.StopCh

	return fmt.Errorf("stopped")
}
