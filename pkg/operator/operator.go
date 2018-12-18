package operator

import (
	"github.com/golang/glog"

	"github.com/openshift/cluster-machine-approver/pkg/boilerplate/controller"

	"k8s.io/apimachinery/pkg/apis/meta/v1"

	certv1beta1 "k8s.io/api/certificates/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers/certificates/v1beta1"
	certificatesv1beta1 "k8s.io/client-go/kubernetes/typed/certificates/v1beta1"
)

type approverController struct {
	csrClient certificatesv1beta1.CertificateSigningRequestsGetter
}

func NewMachineApproverController(cri v1beta1.CertificateSigningRequestInformer, csrClient certificatesv1beta1.CertificateSigningRequestsGetter) controller.Runner {
	c := &approverController{
		csrClient: csrClient,
	}

	add := func(obj v1.Object) bool {
		return true
	}
	return controller.New("MachineApproverController", c,
		controller.WithInformer(cri, controller.FilterFuncs{
			ParentFunc: nil,
			AddFunc:    add,
			UpdateFunc: func(oldObj, newObj v1.Object) bool {
				return true
			},
			DeleteFunc: add,
		}),
	)
}

func (c approverController) Key(namespace, name string) (metav1.Object, error) {
	return c.csrClient.CertificateSigningRequests().Get(name, metav1.GetOptions{})
}

func (c approverController) Sync(obj metav1.Object) error {
	csr := obj.(*certv1beta1.CertificateSigningRequest)
	// Note that you also have to check the uid if you have a local controlled resource, which
	// is dependent on the actual instance, to detect that a CSR was recreated with the same name
	glog.Infof("CSR %s added\n", csr.GetName())

	var alreadyApproved bool
	for _, c := range csr.Status.Conditions {
		if c.Type == certv1beta1.CertificateApproved {
			alreadyApproved = true
			break
		}
	}
	if alreadyApproved {
		glog.Infof("CSR %s is already approved", csr.GetName())
		return nil
	}

	// TODO and CSR checking logic here

	csr.Status.Conditions = append(csr.Status.Conditions, certv1beta1.CertificateSigningRequestCondition{
		Type:           certv1beta1.CertificateApproved,
		Reason:         "NodeCSRApprove",
		Message:        "This CSR was approved by the machine approver operator.",
		LastUpdateTime: metav1.Now(),
	})

	if _, err := c.csrClient.CertificateSigningRequests().UpdateApproval(csr); err != nil {
		return err
	}

	glog.Infof("CSR %s approved", csr.GetName())

	return nil
}
