package istiocsr

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	certmanagerv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/openshift/cert-manager-operator/api/operator/v1alpha1"
	"github.com/openshift/cert-manager-operator/pkg/controller/istiocsr/fakes"
)

func TestReconcile(t *testing.T) {
	// set the operand image env var
	t.Setenv("RELATED_IMAGE_CERT_MANAGER_ISTIOCSR", "registry.redhat.io/cert-manager/cert-manager-istio-csr-rhel9:latest")

	tests := []struct {
		name                    string
		preReq                  func(*Reconciler, *fakes.FakeCtrlClient)
		expectedStatusCondition []metav1.Condition
		requeue                 bool
		wantErr                 string
	}{
		{
			name: "reconciliation successful",
			preReq: func(r *Reconciler, m *fakes.FakeCtrlClient) {
				m.GetCalls(func(ctx context.Context, ns types.NamespacedName, obj client.Object) error {
					switch o := obj.(type) {
					case *v1alpha1.IstioCSR:
						istiocsr := testIstioCSR()
						istiocsr.DeepCopyInto(o)
					case *appsv1.Deployment:
						deployment := testDeployment()
						deployment.DeepCopyInto(o)
					}
					return nil
				})
				m.ExistsCalls(func(ctx context.Context, ns types.NamespacedName, obj client.Object) (bool, error) {
					switch o := obj.(type) {
					case *appsv1.Deployment:
						deployment := testDeployment()
						deployment.DeepCopyInto(o)
					}
					return true, nil
				})
				m.CreateCalls(func(ctx context.Context, obj client.Object, option ...client.CreateOption) error {
					switch o := obj.(type) {
					case *rbacv1.ClusterRoleBinding:
						roleBinding := testClusterRoleBinding()
						roleBinding.DeepCopyInto(o)
					}
					return nil
				})
			},
			expectedStatusCondition: []metav1.Condition{
				{
					Type:   v1alpha1.Ready,
					Status: metav1.ConditionTrue,
					Reason: v1alpha1.ReasonReady,
				},
				{
					Type:   v1alpha1.Degraded,
					Status: metav1.ConditionFalse,
					Reason: v1alpha1.ReasonReady,
				},
			},
			requeue: false,
		},
		{
			name: "reconciliation failed",
			preReq: func(r *Reconciler, m *fakes.FakeCtrlClient) {
				m.GetCalls(func(ctx context.Context, ns types.NamespacedName, obj client.Object) error {
					switch o := obj.(type) {
					case *v1alpha1.IstioCSR:
						istiocsr := testIstioCSR()
						istiocsr.DeepCopyInto(o)
					case *certmanagerv1.Certificate:
						cert := testCertificate()
						cert.DeepCopyInto(o)
					case *rbacv1.ClusterRole:
						role := testClusterRole()
						role.DeepCopyInto(o)
					case *rbacv1.ClusterRoleBinding:
						roleBinding := testClusterRoleBinding()
						roleBinding.DeepCopyInto(o)
					case *appsv1.Deployment:
						deployment := testDeployment()
						deployment.DeepCopyInto(o)
					case *rbacv1.Role:
						var role *rbacv1.Role
						if strings.HasSuffix(ns.Name, "-leases") {
							role = testRoleLeases()
						} else {
							role = testRole()
						}
						role.DeepCopyInto(o)
					case *rbacv1.RoleBinding:
						var roleBinding *rbacv1.RoleBinding
						if strings.HasSuffix(ns.Name, "-leases") {
							roleBinding = testRoleBindingLeases()
						} else {
							roleBinding = testRoleBinding()
						}
						roleBinding.DeepCopyInto(o)
					case *corev1.Service:
						service := testService()
						service.DeepCopyInto(o)
					case *corev1.ServiceAccount:
						serviceAccount := testServiceAccount()
						serviceAccount.DeepCopyInto(o)
					}
					return nil
				})
				m.UpdateWithRetryCalls(func(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
					switch o := obj.(type) {
					case *v1alpha1.IstioCSR:
						// fail the operation where controller is trying to add processed annotation.
						if _, exist := o.GetAnnotations()[controllerProcessedAnnotation]; exist {
							return testError
						}
					}
					return nil
				})
				m.ExistsCalls(func(ctx context.Context, ns types.NamespacedName, obj client.Object) (bool, error) {
					switch o := obj.(type) {
					case *appsv1.Deployment:
						deployment := testDeployment()
						deployment.DeepCopyInto(o)
					}
					return true, nil
				})
				m.CreateCalls(func(ctx context.Context, obj client.Object, option ...client.CreateOption) error {
					switch o := obj.(type) {
					case *rbacv1.ClusterRoleBinding:
						roleBinding := testClusterRoleBinding()
						roleBinding.DeepCopyInto(o)
					}
					return nil
				})
			},
			expectedStatusCondition: []metav1.Condition{
				{
					Type:   v1alpha1.Ready,
					Status: metav1.ConditionFalse,
					Reason: v1alpha1.ReasonInProgress,
				},
				{
					Type:   v1alpha1.Degraded,
					Status: metav1.ConditionFalse,
					Reason: v1alpha1.ReasonReady,
				},
			},
			requeue: true,
			wantErr: `failed to reconcile "istiocsr-test-ns/istiocsr-test-resource" IstioCSR deployment: failed to update processed annotation to istiocsr-test-ns/istiocsr-test-resource: test client error`,
		},
		{
			name: "reconciliation failed with irrecoverable error",
			preReq: func(r *Reconciler, m *fakes.FakeCtrlClient) {
				m.GetCalls(func(ctx context.Context, ns types.NamespacedName, obj client.Object) error {
					switch o := obj.(type) {
					case *v1alpha1.IstioCSR:
						istiocsr := testIstioCSR()
						istiocsr.DeepCopyInto(o)
					case *certmanagerv1.Certificate:
						cert := testCertificate()
						cert.DeepCopyInto(o)
					case *rbacv1.ClusterRole:
						role := testClusterRole()
						role.DeepCopyInto(o)
					case *rbacv1.ClusterRoleBinding:
						roleBinding := testClusterRoleBinding()
						roleBinding.DeepCopyInto(o)
					case *appsv1.Deployment:
						deployment := testDeployment()
						deployment.DeepCopyInto(o)
					case *rbacv1.Role:
						var role *rbacv1.Role
						if strings.HasSuffix(ns.Name, "-leases") {
							role = testRoleLeases()
						} else {
							role = testRole()
						}
						role.DeepCopyInto(o)
					case *rbacv1.RoleBinding:
						var roleBinding *rbacv1.RoleBinding
						if strings.HasSuffix(ns.Name, "-leases") {
							roleBinding = testRoleBindingLeases()
						} else {
							roleBinding = testRoleBinding()
						}
						roleBinding.DeepCopyInto(o)
					case *corev1.Service:
						service := testService()
						service.DeepCopyInto(o)
					case *corev1.ServiceAccount:
						serviceAccount := testServiceAccount()
						serviceAccount.DeepCopyInto(o)
					}
					return nil
				})
				m.ExistsCalls(func(ctx context.Context, ns types.NamespacedName, obj client.Object) (bool, error) {
					switch obj.(type) {
					case *appsv1.Deployment:
						return false, nil
					}
					return true, nil
				})
				// fail the operation where controller is trying to create deployment resource.
				m.CreateCalls(func(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
					switch o := obj.(type) {
					case *appsv1.Deployment:
						return apierrors.NewUnauthorized("test error")
					case *rbacv1.ClusterRoleBinding:
						roleBinding := testClusterRoleBinding()
						roleBinding.DeepCopyInto(o)
					}
					return nil
				})
			},
			expectedStatusCondition: []metav1.Condition{
				{
					Type:   v1alpha1.Ready,
					Status: metav1.ConditionFalse,
					Reason: v1alpha1.ReasonReady,
				},
				{
					Type:   v1alpha1.Degraded,
					Status: metav1.ConditionTrue,
					Reason: v1alpha1.ReasonFailed,
				},
			},
			requeue: false,
			// reconcile does not report back irrecoverable errors
			wantErr: ``,
		},
		{
			name: "reconciliation istiocsr resource does not exist",
			preReq: func(r *Reconciler, m *fakes.FakeCtrlClient) {
				m.GetCalls(func(ctx context.Context, ns types.NamespacedName, obj client.Object) error {
					switch obj.(type) {
					case *v1alpha1.IstioCSR:
						return apierrors.NewNotFound(v1alpha1.Resource("istiocsr"), "default")
					}
					return nil
				})
			},
			requeue: false,
		},
		{
			name: "reconciliation failed to fetch istiocsr resource",
			preReq: func(r *Reconciler, m *fakes.FakeCtrlClient) {
				m.GetCalls(func(ctx context.Context, ns types.NamespacedName, obj client.Object) error {
					switch obj.(type) {
					case *v1alpha1.IstioCSR:
						return apierrors.NewBadRequest("test error")
					}
					return nil
				})
			},
			requeue: false,
			wantErr: `failed to fetch istiocsr.openshift.operator.io "istiocsr-test-ns/istiocsr-test-resource" during reconciliation: test error`,
		},
		{
			name: "reconciliation istiocsr marked for deletion",
			preReq: func(r *Reconciler, m *fakes.FakeCtrlClient) {
				m.GetCalls(func(ctx context.Context, ns types.NamespacedName, obj client.Object) error {
					switch o := obj.(type) {
					case *v1alpha1.IstioCSR:
						istiocsr := testIstioCSR()
						istiocsr.DeletionTimestamp = &metav1.Time{Time: time.Now()}
						istiocsr.DeepCopyInto(o)
					}
					return nil
				})
			},
			requeue: false,
		},
		{
			name: "reconciliation updating istiocsr status subresource failed",
			preReq: func(r *Reconciler, m *fakes.FakeCtrlClient) {
				m.GetCalls(func(ctx context.Context, ns types.NamespacedName, obj client.Object) error {
					switch o := obj.(type) {
					case *v1alpha1.IstioCSR:
						istiocsr := testIstioCSR()
						istiocsr.DeepCopyInto(o)
					case *appsv1.Deployment:
						deployment := testDeployment()
						deployment.DeepCopyInto(o)
					}
					return nil
				})
				m.ExistsCalls(func(ctx context.Context, ns types.NamespacedName, obj client.Object) (bool, error) {
					switch o := obj.(type) {
					case *appsv1.Deployment:
						deployment := testDeployment()
						deployment.DeepCopyInto(o)
					}
					return true, nil
				})
				m.CreateReturns(nil)
				m.StatusUpdateCalls(func(ctx context.Context, obj client.Object, opts ...client.SubResourceUpdateOption) error {
					switch obj.(type) {
					case *v1alpha1.IstioCSR:
						return apierrors.NewBadRequest("test error")
					}
					return nil
				})
			},
			// StatusUpdate fails for ALL IstioCSR calls (including RBAC status
			// updates), so RBAC reconciliation fails with an irrecoverable error
			// before reaching the success conditions path.
			expectedStatusCondition: []metav1.Condition{
				{
					Type:   v1alpha1.Ready,
					Status: metav1.ConditionFalse,
					Reason: v1alpha1.ReasonReady,
				},
				{
					Type:   v1alpha1.Degraded,
					Status: metav1.ConditionTrue,
					Reason: v1alpha1.ReasonFailed,
				},
			},
			requeue: false,
			wantErr: `failed to update istiocsr-test-ns/istiocsr-test-resource status: failed to update istiocsr.openshift.operator.io "istiocsr-test-ns/istiocsr-test-resource" status: test error`,
		},
		{
			name: "reconciliation remove finalizer from istiocsr fails",
			preReq: func(r *Reconciler, m *fakes.FakeCtrlClient) {
				m.GetCalls(func(ctx context.Context, ns types.NamespacedName, obj client.Object) error {
					switch o := obj.(type) {
					case *v1alpha1.IstioCSR:
						istiocsr := testIstioCSR()
						istiocsr.DeletionTimestamp = &metav1.Time{Time: time.Now()}
						istiocsr.Finalizers = []string{finalizer}
						istiocsr.DeepCopyInto(o)
					}
					return nil
				})
				m.UpdateWithRetryCalls(func(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
					switch obj.(type) {
					case *v1alpha1.IstioCSR:
						return testError
					}
					return nil
				})
			},
			requeue: false,
			wantErr: `failed to remove finalizers on "istiocsr-test-ns/istiocsr-test-resource" istiocsr.openshift.operator.io with test client error`,
		},
		{
			name: "reconciliation adding finalizer to istiocsr fails",
			preReq: func(r *Reconciler, m *fakes.FakeCtrlClient) {
				m.GetCalls(func(ctx context.Context, ns types.NamespacedName, obj client.Object) error {
					switch o := obj.(type) {
					case *v1alpha1.IstioCSR:
						istiocsr := testIstioCSR()
						istiocsr.DeepCopyInto(o)
					}
					return nil
				})
				m.UpdateWithRetryCalls(func(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
					switch obj.(type) {
					case *v1alpha1.IstioCSR:
						return testError
					}
					return nil
				})
			},
			requeue: false,
			wantErr: `failed to update "istiocsr-test-ns/istiocsr-test-resource" istiocsr.openshift.operator.io with finalizers: failed to add finalizers on "istiocsr-test-ns/istiocsr-test-resource" istiocsr.openshift.operator.io with test client error`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := testReconciler(t)
			mock := &fakes.FakeCtrlClient{}
			if tt.preReq != nil {
				tt.preReq(r, mock)
			}
			r.ctrlClient = mock
			istiocsr := testIstioCSR()
			result, err := r.Reconcile(context.Background(),
				ctrl.Request{
					NamespacedName: types.NamespacedName{Name: istiocsr.GetName(), Namespace: istiocsr.GetNamespace()},
				},
			)
			if (tt.wantErr != "" || err != nil) && (err == nil || err.Error() != tt.wantErr) {
				t.Errorf("Reconcile() err: %v, wantErr: %v", err, tt.wantErr)
			}
			if tt.requeue && result.IsZero() {
				t.Errorf("Reconcile() expected requeue to be set")
			}
			// Reconcile operates on an internally-fetched IstioCSR, not the local
			// variable. RBAC reconciliation also calls StatusUpdate to persist
			// clusterrole/rolebinding names, so the condition update is always the
			// last StatusUpdate call.
			if len(tt.expectedStatusCondition) > 0 {
				n := mock.StatusUpdateCallCount()
				if n == 0 {
					t.Errorf("Reconcile() expected StatusUpdate to be called for condition checking")
				} else {
					_, updatedObj, _ := mock.StatusUpdateArgsForCall(n - 1)
					updatedIstiocsr, ok := updatedObj.(*v1alpha1.IstioCSR)
					if !ok {
						t.Errorf("Reconcile() StatusUpdate called with non-IstioCSR: %T", updatedObj)
					} else {
						for _, want := range tt.expectedStatusCondition {
							got := updatedIstiocsr.Status.GetCondition(want.Type)
							if got == nil {
								t.Errorf("Reconcile() condition %q missing from status", want.Type)
								continue
							}
							if got.Status != want.Status || got.Reason != want.Reason {
								t.Errorf("Reconcile() condition %q: got {Status:%s Reason:%s}, want {Status:%s Reason:%s}",
									want.Type, got.Status, got.Reason, want.Status, want.Reason)
							}
						}
					}
				}
			}
		})
	}
}

func TestProcessReconcileRequest(t *testing.T) {
	// set the operand image env var
	t.Setenv("RELATED_IMAGE_CERT_MANAGER_ISTIOCSR", "registry.redhat.io/cert-manager/cert-manager-istio-csr-rhel9:latest")

	tests := []struct {
		name                    string
		getIstioCSR             func() *v1alpha1.IstioCSR
		preReq                  func(*Reconciler, *fakes.FakeCtrlClient)
		expectedStatusCondition []metav1.Condition
		expectedAnnotations     map[string]string
		wantErr                 string
	}{
		{
			name: "reconciliation successful",
			getIstioCSR: func() *v1alpha1.IstioCSR {
				return testIstioCSR()
			},
			preReq: func(r *Reconciler, m *fakes.FakeCtrlClient) {
				m.GetCalls(func(ctx context.Context, ns types.NamespacedName, obj client.Object) error {
					switch o := obj.(type) {
					case *appsv1.Deployment:
						deployment := testDeployment()
						deployment.DeepCopyInto(o)
					}
					return nil
				})
				m.ExistsCalls(func(ctx context.Context, ns types.NamespacedName, obj client.Object) (bool, error) {
					switch o := obj.(type) {
					case *appsv1.Deployment:
						deployment := testDeployment()
						deployment.DeepCopyInto(o)
					}
					return true, nil
				})
				m.CreateCalls(func(ctx context.Context, obj client.Object, option ...client.CreateOption) error {
					switch o := obj.(type) {
					case *rbacv1.ClusterRoleBinding:
						roleBinding := testClusterRoleBinding()
						roleBinding.DeepCopyInto(o)
					}
					return nil
				})
			},
			expectedStatusCondition: []metav1.Condition{
				{
					Type:    v1alpha1.Ready,
					Status:  metav1.ConditionTrue,
					Reason:  v1alpha1.ReasonReady,
					Message: "reconciliation successful",
				},
				{
					Type:   v1alpha1.Degraded,
					Status: metav1.ConditionFalse,
					Reason: v1alpha1.ReasonReady,
				},
			},
			expectedAnnotations: map[string]string{
				controllerProcessedAnnotation: "true",
			},
		},
		{
			name: "reconciliation of existing istiocsr",
			getIstioCSR: func() *v1alpha1.IstioCSR {
				istiocsr := testIstioCSR()
				istiocsr.Annotations = map[string]string{
					controllerProcessedAnnotation: "true",
				}
				return istiocsr
			},
			preReq: func(r *Reconciler, m *fakes.FakeCtrlClient) {
				m.GetCalls(func(ctx context.Context, ns types.NamespacedName, obj client.Object) error {
					switch o := obj.(type) {
					case *appsv1.Deployment:
						deployment := testDeployment()
						deployment.DeepCopyInto(o)
					}
					return nil
				})
				m.ExistsCalls(func(ctx context.Context, ns types.NamespacedName, obj client.Object) (bool, error) {
					switch o := obj.(type) {
					case *appsv1.Deployment:
						deployment := testDeployment()
						deployment.DeepCopyInto(o)
					}
					return true, nil
				})
				m.CreateCalls(func(ctx context.Context, obj client.Object, option ...client.CreateOption) error {
					switch o := obj.(type) {
					case *rbacv1.ClusterRoleBinding:
						roleBinding := testClusterRoleBinding()
						roleBinding.DeepCopyInto(o)
					}
					return nil
				})
			},
			expectedStatusCondition: []metav1.Condition{
				{
					Type:    v1alpha1.Ready,
					Status:  metav1.ConditionTrue,
					Reason:  v1alpha1.ReasonReady,
					Message: "reconciliation successful",
				},
				{
					Type:   v1alpha1.Degraded,
					Status: metav1.ConditionFalse,
					Reason: v1alpha1.ReasonReady,
				},
			},
			expectedAnnotations: map[string]string{
				controllerProcessedAnnotation: "true",
			},
		},
		{
			name: "reconciliation of duplicate istiocsr with annotation present",
			getIstioCSR: func() *v1alpha1.IstioCSR {
				istiocsr := testIstioCSR()
				istiocsr.Annotations = map[string]string{
					controllerProcessingRejectedAnnotation: "true",
				}
				return istiocsr
			},
			preReq: func(r *Reconciler, m *fakes.FakeCtrlClient) {},
			expectedStatusCondition: []metav1.Condition{
				{
					Type:    v1alpha1.Ready,
					Status:  metav1.ConditionFalse,
					Reason:  v1alpha1.ReasonFailed,
					Message: "multiple instances of istiocsr exists, istiocsr-test-ns/istiocsr-test-resource will not be processed",
				},
			},
			expectedAnnotations: map[string]string{
				controllerProcessingRejectedAnnotation: "true",
			},
		},
		{
			name: "validating multiple istiocsrs' fails while listing",
			getIstioCSR: func() *v1alpha1.IstioCSR {
				return testIstioCSR()
			},
			preReq: func(r *Reconciler, m *fakes.FakeCtrlClient) {
				m.ListCalls(func(ctx context.Context, list client.ObjectList, option ...client.ListOption) error {
					switch list.(type) {
					case *v1alpha1.IstioCSRList:
						return testError
					}
					return nil
				})
			},
			wantErr: `failed to fetch list of istiocsr resources: test client error`,
		},
		{
			name: "validating multiple istiocsrs' successful by ignoring latest instance",
			getIstioCSR: func() *v1alpha1.IstioCSR {
				istiocsr := testIstioCSR()
				istiocsr.SetNamespace("istiocsr3")
				istiocsr.SetCreationTimestamp(metav1.NewTime(time.Now().Add(time.Second * 2)))
				return istiocsr
			},
			preReq: func(r *Reconciler, m *fakes.FakeCtrlClient) {
				m.ListCalls(func(ctx context.Context, list client.ObjectList, option ...client.ListOption) error {
					switch l := list.(type) {
					case *v1alpha1.IstioCSRList:
						istiocsr1 := testIstioCSR()
						istiocsr2 := testIstioCSR()
						istiocsr3 := testIstioCSR()

						istiocsr1.SetNamespace("istiocsr1")
						istiocsr2.SetNamespace("istiocsr2")
						istiocsr3.SetNamespace("istiocsr3")

						istiocsr1.SetCreationTimestamp(metav1.NewTime(time.Now()))
						istiocsr2.SetCreationTimestamp(metav1.NewTime(time.Now().Add(time.Second)))
						istiocsr3.SetCreationTimestamp(metav1.NewTime(time.Now().Add(time.Second * 2)))

						l.Items = []v1alpha1.IstioCSR{*istiocsr1, *istiocsr2, *istiocsr3}
					}
					return nil
				})
			},
			expectedStatusCondition: []metav1.Condition{
				{
					Type:    v1alpha1.Ready,
					Status:  metav1.ConditionFalse,
					Reason:  v1alpha1.ReasonFailed,
					Message: "multiple instances of istiocsr exists, istiocsr3/istiocsr-test-resource will not be processed",
				},
			},
			expectedAnnotations: map[string]string{
				controllerProcessingRejectedAnnotation: "true",
			},
		},
		{
			name: "validating multiple istiocsrs' failed to update status",
			getIstioCSR: func() *v1alpha1.IstioCSR {
				istiocsr := testIstioCSR()
				istiocsr.SetNamespace("istiocsr3")
				istiocsr.SetCreationTimestamp(metav1.NewTime(time.Now().Add(time.Second * 2)))
				return istiocsr
			},
			preReq: func(r *Reconciler, m *fakes.FakeCtrlClient) {
				m.ListCalls(func(ctx context.Context, list client.ObjectList, option ...client.ListOption) error {
					switch l := list.(type) {
					case *v1alpha1.IstioCSRList:
						istiocsr1 := testIstioCSR()
						istiocsr2 := testIstioCSR()
						istiocsr3 := testIstioCSR()

						istiocsr1.SetNamespace("istiocsr1")
						istiocsr2.SetNamespace("istiocsr2")
						istiocsr3.SetNamespace("istiocsr3")

						istiocsr1.SetCreationTimestamp(metav1.NewTime(time.Now()))
						istiocsr2.SetCreationTimestamp(metav1.NewTime(time.Now().Add(time.Second)))
						istiocsr3.SetCreationTimestamp(metav1.NewTime(time.Now().Add(time.Second * 2)))

						l.Items = []v1alpha1.IstioCSR{*istiocsr1, *istiocsr2, *istiocsr3}
					}
					m.StatusUpdateCalls(func(ctx context.Context, obj client.Object, option ...client.SubResourceUpdateOption) error {
						switch obj.(type) {
						case *v1alpha1.IstioCSR:
							return testError
						}
						return nil
					})
					return nil
				})
			},
			expectedStatusCondition: []metav1.Condition{
				{
					Type:    v1alpha1.Ready,
					Status:  metav1.ConditionFalse,
					Reason:  v1alpha1.ReasonFailed,
					Message: "multiple instances of istiocsr exists, istiocsr3/istiocsr-test-resource will not be processed",
				},
			},
			expectedAnnotations: map[string]string{
				controllerProcessingRejectedAnnotation: "true",
			},
			wantErr: `failed to update istiocsr3/istiocsr-test-resource status: failed to update istiocsr.openshift.operator.io "istiocsr3/istiocsr-test-resource" status: test client error`,
		},
		{
			name: "validating multiple istiocsrs' failed to update annotations",
			getIstioCSR: func() *v1alpha1.IstioCSR {
				istiocsr := testIstioCSR()
				istiocsr.SetNamespace("istiocsr3")
				istiocsr.SetCreationTimestamp(metav1.NewTime(time.Now().Add(time.Second * 2)))
				return istiocsr
			},
			preReq: func(r *Reconciler, m *fakes.FakeCtrlClient) {
				m.ListCalls(func(ctx context.Context, list client.ObjectList, option ...client.ListOption) error {
					switch l := list.(type) {
					case *v1alpha1.IstioCSRList:
						istiocsr1 := testIstioCSR()
						istiocsr2 := testIstioCSR()
						istiocsr3 := testIstioCSR()

						istiocsr1.SetNamespace("istiocsr1")
						istiocsr2.SetNamespace("istiocsr2")
						istiocsr3.SetNamespace("istiocsr3")

						istiocsr1.SetCreationTimestamp(metav1.NewTime(time.Now()))
						istiocsr2.SetCreationTimestamp(metav1.NewTime(time.Now().Add(time.Second)))
						istiocsr3.SetCreationTimestamp(metav1.NewTime(time.Now().Add(time.Second * 2)))

						l.Items = []v1alpha1.IstioCSR{*istiocsr1, *istiocsr2, *istiocsr3}
					}
					m.UpdateWithRetryCalls(func(ctx context.Context, obj client.Object, option ...client.UpdateOption) error {
						switch obj.(type) {
						case *v1alpha1.IstioCSR:
							return testError
						}
						return nil
					})
					return nil
				})
			},
			expectedStatusCondition: []metav1.Condition{
				{
					Type:    v1alpha1.Ready,
					Status:  metav1.ConditionFalse,
					Reason:  v1alpha1.ReasonFailed,
					Message: "multiple instances of istiocsr exists, istiocsr3/istiocsr-test-resource will not be processed",
				},
			},
			expectedAnnotations: map[string]string{
				controllerProcessingRejectedAnnotation: "true",
			},
			wantErr: `failed to update reject processing annotation to istiocsr3/istiocsr-test-resource: test client error`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := testReconciler(t)
			mock := &fakes.FakeCtrlClient{}
			if tt.preReq != nil {
				tt.preReq(r, mock)
			}
			r.ctrlClient = mock
			istiocsr := tt.getIstioCSR()
			_, err := r.processReconcileRequest(istiocsr,
				types.NamespacedName{Name: istiocsr.GetName(), Namespace: istiocsr.GetNamespace()})
			if (tt.wantErr != "" || err != nil) && (err == nil || err.Error() != tt.wantErr) {
				t.Errorf("processReconcileRequest() err: %v, wantErr: %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(istiocsr.Annotations, tt.expectedAnnotations) {
				t.Errorf("processReconcileRequest() annotations: %v, expectedAnnotations: %v", istiocsr.Annotations, tt.expectedAnnotations)
			}
			for _, want := range tt.expectedStatusCondition {
				got := istiocsr.Status.GetCondition(want.Type)
				if got == nil {
					t.Errorf("processReconcileRequest() condition %q missing from status", want.Type)
					continue
				}
				if got.Status != want.Status || got.Reason != want.Reason || got.Message != want.Message {
					t.Errorf("processReconcileRequest() condition %q: got {Status:%s Reason:%s Message:%s}, want {Status:%s Reason:%s Message:%s}",
						want.Type, got.Status, got.Reason, got.Message, want.Status, want.Reason, want.Message)
				}
			}
		})
	}
}
