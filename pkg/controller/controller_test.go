package controller

import (
	"errors"
	"testing"
	"time"

	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	machinehandlerpkg "github.com/openshift/cluster-machine-approver/pkg/machinehandler"
)

// Test_reconcileCSR_nodeNotSettled covers how the controller schedules a second
// look at an existing-node client CSR whose Node still reports Ready=True.
//
// Nothing else will bring such a CSR back: the controller watches CSRs and the
// kubelet CA ConfigMap, not Nodes, so a Node merely leaving Ready produces no
// event. Without the requeue below, a kubelet that re-bootstrapped inside the
// node monitor grace period would wait on a CSR that is never looked at again.
func Test_reconcileCSR_nodeNotSettled(t *testing.T) {
	// A node-bootstrapper client CSR for node "panda", matching clientGood's CN.
	csrFor := func(age time.Duration) certificatesv1.CertificateSigningRequest {
		return certificatesv1.CertificateSigningRequest{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "csr-panda",
				CreationTimestamp: metav1.NewTime(time.Now().Add(-age)),
			},
			Spec: certificatesv1.CertificateSigningRequestSpec{
				Request: []byte(clientGood),
				Usages: []certificatesv1.KeyUsage{
					certificatesv1.UsageKeyEncipherment,
					certificatesv1.UsageDigitalSignature,
					certificatesv1.UsageClientAuth,
				},
				Username: "system:serviceaccount:openshift-machine-config-operator:node-bootstrapper",
				Groups: []string{
					"system:authenticated",
					"system:serviceaccounts:openshift-machine-config-operator",
					"system:serviceaccounts",
				},
			},
		}
	}

	nodeWithReady := func(ready corev1.ConditionStatus) *corev1.Node {
		return &corev1.Node{
			ObjectMeta: metav1.ObjectMeta{Name: "panda", UID: "panda-uid"},
			Status: corev1.NodeStatus{
				Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: ready}},
			},
		}
	}

	machines := []machinehandlerpkg.Machine{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "machine-panda"},
			Status: machinehandlerpkg.MachineStatus{
				NodeRef: &corev1.ObjectReference{Name: "panda", UID: "panda-uid"},
				Addresses: []corev1.NodeAddress{
					{Type: corev1.NodeInternalDNS, Address: "panda"},
				},
			},
		},
	}

	tests := []struct {
		name       string
		csrAge     time.Duration
		wantResult reconcile.Result
	}{
		{
			// Well inside the window: come back and look again shortly.
			name:       "recent CSR is requeued",
			csrAge:     5 * time.Second,
			wantResult: reconcile.Result{RequeueAfter: nodeSettleRetryInterval},
		},
		{
			name:       "CSR just inside the retry window is requeued",
			csrAge:     nodeSettleRetryWindow - time.Minute,
			wantResult: reconcile.Result{RequeueAfter: nodeSettleRetryInterval},
		},
		{
			// A node still Ready this long after the CSR was created is not the
			// re-bootstrap case, so stop requeueing rather than spinning forever.
			name:       "CSR past the retry window stops being requeued",
			csrAge:     nodeSettleRetryWindow + time.Minute,
			wantResult: reconcile.Result{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &CertificateApprover{
				WorkloadClient: fake.NewFakeClient(nodeWithReady(corev1.ConditionTrue)),
			}

			result, err := m.reconcileCSR(t.Context(), csrFor(tt.csrAge), machines)
			if err != nil {
				t.Fatalf("reconcileCSR() unexpected error: %v", err)
			}
			if result != tt.wantResult {
				t.Errorf("reconcileCSR() result = %+v, want %+v", result, tt.wantResult)
			}
		})
	}

	// Once the node leaves Ready, the same CSR is no longer deferred: the next
	// look authorizes it. reconcileCSR goes on to call approve(), which needs a
	// live API server, so assert the transition through authorizeCSR instead.
	t.Run("readiness transition makes the CSR authorizable", func(t *testing.T) {
		csr := csrFor(5 * time.Second)
		parsedCSR, err := parseCSR(&csr)
		if err != nil {
			t.Fatalf("parseCSR() unexpected error: %v", err)
		}

		readyClient := fake.NewFakeClient(nodeWithReady(corev1.ConditionTrue))
		authorize, err := authorizeCSR(t.Context(), readyClient, ClusterMachineApproverConfig{}, machines, &csr, parsedCSR)
		if authorize {
			t.Error("authorizeCSR() authorized while the node was still Ready, want deferred")
		}
		var notSettled *nodeNotSettledError
		if !errors.As(err, &notSettled) {
			t.Fatalf("authorizeCSR() error = %v, want *nodeNotSettledError", err)
		}

		// The node monitor marks the unreachable node's readiness Unknown.
		notReadyClient := fake.NewFakeClient(nodeWithReady(corev1.ConditionUnknown))
		authorize, err = authorizeCSR(t.Context(), notReadyClient, ClusterMachineApproverConfig{}, machines, &csr, parsedCSR)
		if err != nil {
			t.Fatalf("authorizeCSR() unexpected error after readiness transition: %v", err)
		}
		if !authorize {
			t.Error("authorizeCSR() did not authorize after the node left Ready, want authorized")
		}
	})
}
