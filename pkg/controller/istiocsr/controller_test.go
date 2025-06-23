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
					Reason: v1alpha1.ReasonFailed,
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
					Reason: v1alpha1.ReasonFailed,
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
			for _, c1 := range istiocsr.Status.Conditions {
				for _, c2 := range tt.expectedStatusCondition {
					if c1.Type == c2.Type {
						if c1.Status != c2.Status || c1.Reason != c2.Reason {
							t.Errorf("Reconcile() condition: %+v, expectedStatusCondition: %+v", c1, c2)
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
			for _, c1 := range istiocsr.Status.Conditions {
				for _, c2 := range tt.expectedStatusCondition {
					if c1.Type == c2.Type {
						if c1.Status != c2.Status || c1.Reason != c2.Reason || c1.Message != c2.Message {
							t.Errorf("processReconcileRequest() condition: %+v, expectedStatusCondition: %+v", c1, c2)
						}
					}
				}
			}
		})
	}
}

func TestCM546RaceConditionFix(t *testing.T) {
	// Test for CM-546: Verify that Ready condition is always set atomically
	// with Degraded condition to prevent race conditions where Ready condition goes missing
	
	t.Setenv("RELATED_IMAGE_CERT_MANAGER_ISTIOCSR", "registry.redhat.io/cert-manager/cert-manager-istio-csr-rhel9:latest")
	
	r := testReconciler(t)
	mock := &fakes.FakeCtrlClient{}
	
	// Simulate successful reconciliation scenario
	mock.GetCalls(func(ctx context.Context, ns types.NamespacedName, obj client.Object) error {
		switch o := obj.(type) {
		case *appsv1.Deployment:
			deployment := testDeployment()
			deployment.DeepCopyInto(o)
		}
		return nil
	})
	mock.ExistsCalls(func(ctx context.Context, ns types.NamespacedName, obj client.Object) (bool, error) {
		switch o := obj.(type) {
		case *appsv1.Deployment:
			deployment := testDeployment()
			deployment.DeepCopyInto(o)
		}
		return true, nil
	})
	mock.CreateCalls(func(ctx context.Context, obj client.Object, option ...client.CreateOption) error {
		switch o := obj.(type) {
		case *rbacv1.ClusterRoleBinding:
			roleBinding := testClusterRoleBinding()
			roleBinding.DeepCopyInto(o)
		}
		return nil
	})
	
	r.ctrlClient = mock
	istiocsr := testIstioCSR()
	
	// Execute the reconciliation
	_, err := r.processReconcileRequest(istiocsr,
		types.NamespacedName{Name: istiocsr.GetName(), Namespace: istiocsr.GetNamespace()})
	
	if err != nil {
		t.Errorf("processReconcileRequest() unexpected error: %v", err)
	}
	
	// Verify that BOTH Ready and Degraded conditions are present
	var readyCondition, degradedCondition *metav1.Condition
	for i := range istiocsr.Status.Conditions {
		switch istiocsr.Status.Conditions[i].Type {
		case v1alpha1.Ready:
			readyCondition = &istiocsr.Status.Conditions[i]
		case v1alpha1.Degraded:
			degradedCondition = &istiocsr.Status.Conditions[i]
		}
	}
	
	// Assert Ready condition exists and is correctly set
	if readyCondition == nil {
		t.Error("CM-546: Ready condition is missing - this should not happen after our fix")
	} else {
		if readyCondition.Status != metav1.ConditionTrue {
			t.Errorf("CM-546: Ready condition status expected True, got %v", readyCondition.Status)
		}
		if readyCondition.Reason != v1alpha1.ReasonReady {
			t.Errorf("CM-546: Ready condition reason expected %v, got %v", v1alpha1.ReasonReady, readyCondition.Reason)
		}
		if readyCondition.Message != "reconciliation successful" {
			t.Errorf("CM-546: Ready condition message expected 'reconciliation successful', got %v", readyCondition.Message)
		}
	}
	
	// Assert Degraded condition exists and is correctly set
	if degradedCondition == nil {
		t.Error("CM-546: Degraded condition is missing")
	} else {
		if degradedCondition.Status != metav1.ConditionFalse {
			t.Errorf("CM-546: Degraded condition status expected False, got %v", degradedCondition.Status)
		}
		if degradedCondition.Reason != v1alpha1.ReasonReady {
			t.Errorf("CM-546: Degraded condition reason expected %v, got %v", v1alpha1.ReasonReady, degradedCondition.Reason)
		}
	}
	
	// Ensure both conditions have recent timestamps (indicating they were set atomically)
	if readyCondition != nil && degradedCondition != nil {
		timeDiff := readyCondition.LastTransitionTime.Time.Sub(degradedCondition.LastTransitionTime.Time)
		if timeDiff < 0 {
			timeDiff = -timeDiff
		}
		// Conditions should be set within a very short time window (< 1 second)
		// indicating they were set atomically in the same reconciliation cycle
		if timeDiff.Seconds() > 1.0 {
			t.Errorf("CM-546: Conditions were not set atomically - time difference: %v", timeDiff)
		}
	}
}
