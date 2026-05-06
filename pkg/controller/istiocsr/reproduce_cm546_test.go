package istiocsr

// Reproduction test for CM-546: IstioCSR "type: Ready" condition is missing
// on the first successful reconciliation due to Go short-circuit || evaluation.
//
// The bug: processReconcileRequest uses:
//
//	if istiocsr.Status.SetCondition(Degraded,...) || istiocsr.Status.SetCondition(Ready,...) {
//	    updateCondition(...)
//	}
//
// When Degraded is a new condition (first reconciliation), SetCondition(Degraded,...)
// returns true, and Go short-circuits — SetCondition(Ready,...) is never called.
// The Ready condition is silently omitted from the status update.

import (
	"context"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/openshift/cert-manager-operator/api/operator/v1alpha1"
	"github.com/openshift/cert-manager-operator/pkg/controller/istiocsr/fakes"
)

func TestCM546_ReadyConditionPresentOnFirstReconciliation(t *testing.T) {
	t.Setenv("RELATED_IMAGE_CERT_MANAGER_ISTIOCSR", "registry.redhat.io/cert-manager/cert-manager-istio-csr-rhel9:latest")

	r := testReconciler(t)
	mock := &fakes.FakeCtrlClient{}

	// Set up a successful reconciliation scenario with a brand-new IstioCSR
	// (empty status, no processed annotation — first reconciliation).
	mock.ExistsCalls(func(ctx context.Context, ns types.NamespacedName, obj client.Object) (bool, error) {
		switch o := obj.(type) {
		case *appsv1.Deployment:
			testDeployment().DeepCopyInto(o)
		}
		return true, nil
	})
	mock.GetCalls(func(ctx context.Context, ns types.NamespacedName, obj client.Object) error {
		switch o := obj.(type) {
		case *appsv1.Deployment:
			testDeployment().DeepCopyInto(o)
		}
		return nil
	})
	mock.CreateCalls(func(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
		switch o := obj.(type) {
		case *rbacv1.ClusterRoleBinding:
			testClusterRoleBinding().DeepCopyInto(o)
		}
		return nil
	})

	r.ctrlClient = mock
	istiocsr := testIstioCSR() // fresh IstioCSR: no annotations, empty status

	_, err := r.processReconcileRequest(istiocsr,
		types.NamespacedName{Name: istiocsr.GetName(), Namespace: istiocsr.GetNamespace()})
	if err != nil {
		t.Fatalf("processReconcileRequest() unexpected error: %v", err)
	}

	// Verify both conditions are present and correct.
	wantConditions := []metav1.Condition{
		{Type: v1alpha1.Ready, Status: metav1.ConditionTrue, Reason: v1alpha1.ReasonReady},
		{Type: v1alpha1.Degraded, Status: metav1.ConditionFalse, Reason: v1alpha1.ReasonReady},
	}
	for _, want := range wantConditions {
		got := istiocsr.Status.GetCondition(want.Type)
		if got == nil {
			t.Errorf("condition %q is missing from status after first reconciliation (CM-546)", want.Type)
			continue
		}
		if got.Status != want.Status || got.Reason != want.Reason {
			t.Errorf("condition %q: got {Status:%s Reason:%s}, want {Status:%s Reason:%s}",
				want.Type, got.Status, got.Reason, want.Status, want.Reason)
		}
	}
}
