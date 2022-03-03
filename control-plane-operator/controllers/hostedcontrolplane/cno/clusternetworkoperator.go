package cno

import (
	"fmt"
	hyperv1 "github.com/openshift/hypershift/api/v1alpha1"
	"github.com/openshift/hypershift/control-plane-operator/controllers/hostedcontrolplane/kas"
	"github.com/openshift/hypershift/control-plane-operator/controllers/hostedcontrolplane/manifests"
	"github.com/openshift/hypershift/support/config"
	"github.com/openshift/hypershift/support/util"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilpointer "k8s.io/utils/pointer"
)

const operatorName = "cluster-network-operator"

type Images struct {
	NetworkOperator              string
	SDN                          string
	KubeProxy                    string
	KubeRBACProxy                string
	Multus                       string
	MultusAdmissionController    string
	CNIPlugins                   string
	BondCNIPlugin                string
	WhereaboutsCNI               string
	RouteOverrideCNI             string
	MultusNetworkPolicy          string
	OVN                          string
	EgressRouterCNI              string
	KuryrDaemon                  string
	KuryrController              string
	NetworkMetricsDaemon         string
	NetworkCheckSource           string
	NetworkCheckTarget           string
	CloudNetworkConfigController string
}

type Params struct {
	ReleaseVersion          string
	AvailabilityProberImage string
	APIServerAddress        string
	APIServerPort           int32
	Images                  Images
	OwnerRef                config.OwnerRef
	DeploymentConfig        config.DeploymentConfig
}

func NewParams(hcp *hyperv1.HostedControlPlane, version string, images map[string]string, setDefaultSecurityContext bool) Params {
	p := Params{
		Images: Images{
			//NetworkOperator:           images["cluster-network-operator"],
			NetworkOperator:              "quay.io/pdiak/cno:94b6325f-dirty",
			SDN:                          images["sdn"],
			KubeProxy:                    images["kube-proxy"],
			KubeRBACProxy:                images["kube-rbac-proxy"],
			Multus:                       images["multus-cni"],
			MultusAdmissionController:    images["multus-admission-controller"],
			CNIPlugins:                   images["container-networking-plugins"],
			BondCNIPlugin:                images["network-interface-bond-cni"],
			WhereaboutsCNI:               images["multus-whereabouts-ipam-cni"],
			RouteOverrideCNI:             images["multus-route-override-cni"],
			MultusNetworkPolicy:          images["multus-networkpolicy"],
			OVN:                          images["ovn-kubernetes"],
			EgressRouterCNI:              images["egress-router-cni"],
			KuryrDaemon:                  images["kuryr-cni"],
			KuryrController:              images["kuryr-controller"],
			NetworkMetricsDaemon:         images["network-metrics-daemon"],
			NetworkCheckSource:           images["cluster-network-operator"],
			NetworkCheckTarget:           images["cluster-network-operator"],
			CloudNetworkConfigController: images["cloud-network-config-controller"],
		},
		ReleaseVersion:          version,
		AvailabilityProberImage: images[util.AvailabilityProberImageName],
		OwnerRef:                config.OwnerRefFrom(hcp),
	}

	p.DeploymentConfig.Scheduling.PriorityClass = config.DefaultPriorityClass
	p.DeploymentConfig.SetColocation(hcp)
	p.DeploymentConfig.SetRestartAnnotation(hcp.ObjectMeta)
	p.DeploymentConfig.SetReleaseImageAnnotation(hcp.Spec.ReleaseImage)
	p.DeploymentConfig.SetControlPlaneIsolation(hcp)
	p.DeploymentConfig.Replicas = 1
	p.DeploymentConfig.SetDefaultSecurityContext = setDefaultSecurityContext
	p.APIServerAddress = hcp.Status.ControlPlaneEndpoint.Host
	p.APIServerPort = hcp.Status.ControlPlaneEndpoint.Port

	return p
}

func ReconcileServiceAccount(sa *corev1.ServiceAccount, ownerRef config.OwnerRef) error {
	ownerRef.ApplyTo(sa)
	return nil
}

func ReconcileRole(role *rbacv1.Role, ownerRef config.OwnerRef) error {
	ownerRef.ApplyTo(role)
	role.Rules = []rbacv1.PolicyRule{
		{
			// TODO: Narrow down once known what we actually need
			APIGroups: []string{corev1.SchemeGroupVersion.Group},
			Resources: []string{
				"configmaps",
				"pods",
				"deployments",
				"secrets",
			},
			Verbs: []string{
				"get",
				"patch",
				"update",
				"create",
				"list",
				"watch",
			},
		},
		{
			// Access to the finalizers subresource is required by the
			// hosted-cluster-config-operator due to an OpenShift requirement
			// that setting an owner of a resource requires write access
			// to the finalizers of the owner resource.
			APIGroups: []string{hyperv1.GroupVersion.Group},
			Resources: []string{
				"hostedcontrolplanes/finalizers",
			},
			Verbs: []string{
				"get",
				"update",
				"patch",
				"delete",
			},
		},
	}
	return nil
}

func ReconcileRoleBinding(rb *rbacv1.RoleBinding, ownerRef config.OwnerRef) error {
	ownerRef.ApplyTo(rb)
	rb.RoleRef = rbacv1.RoleRef{
		APIGroup: rbacv1.SchemeGroupVersion.Group,
		Kind:     "Role",
		Name:     manifests.ClusterNetworkOperatorRoleBinding("").Name,
	}
	rb.Subjects = []rbacv1.Subject{
		{
			Kind: "ServiceAccount",
			Name: manifests.ClusterNetworkOperatorServiceAccount("").Name,
		},
	}
	return nil
}

func ReconcileDeployment(dep *appsv1.Deployment, params Params, apiPort *int32) {
	params.OwnerRef.ApplyTo(dep)

	dep.Spec.Replicas = utilpointer.Int32(1)
	dep.Spec.Selector = &metav1.LabelSelector{MatchLabels: map[string]string{"name": operatorName}}
	dep.Spec.Strategy.Type = appsv1.RecreateDeploymentStrategyType
	if dep.Spec.Template.Annotations == nil {
		dep.Spec.Template.Annotations = map[string]string{}
	}
	dep.Spec.Template.Annotations["target.workload.openshift.io/management"] = `{"effect": "PreferredDuringScheduling"}`
	if dep.Spec.Template.Labels == nil {
		dep.Spec.Template.Labels = map[string]string{}
	}
	dep.Spec.Template.Labels["name"] = operatorName
	dep.Spec.Template.Spec.ServiceAccountName = manifests.ClusterNetworkOperatorServiceAccount("").Name
	dep.Spec.Template.Spec.Containers = []corev1.Container{{
		Command: []string{"/bin/bash"},
		Args: []string{"-c", `
#!/bin/bash
set -x
server=https://${KUBERNETES_SERVICE_HOST}:${KUBERNETES_SERVICE_PORT}
sa_dir=/var/run/secrets/kubernetes.io/serviceaccount/

ca=$(cat ${sa_dir}/ca.crt | base64 -w 0)
token=$(cat ${sa_dir}/token)
namespace=$(cat ${sa_dir}/namespace)

echo "
apiVersion: v1
kind: Config
clusters:
- name: management-cluster
  cluster:
    certificate-authority-data: ${ca}
    server: ${server}
contexts:
- name: management-context
  context:
    cluster: management-cluster
    namespace: default
    user: cno-user
current-context: management-context
users:
- name: cno-user
  user:
    token: ${token}
" > /tmp/management.kubeconfig
export KUBERNETES_SERVICE_HOST=${DEFAULT_KUBERNETES_SERVICE_HOST}
export KUBERNETES_SERVICE_PORT=${DEFAULT_KUBERNETES_SERVICE_PORT}
exec /usr/bin/cluster-network-operator start --kubeconfig=/etc/hosted-kubernetes/kubeconfig --extra-clusters=management=/tmp/management.kubeconfig --namespace=openshift-network-operator --listen=0.0.0.0:9104`,
		},
		Env: []corev1.EnvVar{
			{Name: "RELEASE_VERSION", Value: params.ReleaseVersion},
			// TODO: Fix KUBERNETES_SERVICE_HOST/KUBERNETES_SERVICE_PORT handling in CNO and get rid of the following hack
			{Name: "DEFAULT_KUBERNETES_SERVICE_HOST", Value: params.APIServerAddress},
			{Name: "DEFAULT_KUBERNETES_SERVICE_PORT", Value: fmt.Sprint(params.APIServerPort)},
			{Name: "OVN_NB_RAFT_ELECTION_TIMER", Value: "10"},
			{Name: "OVN_SB_RAFT_ELECTION_TIMER", Value: "16"},
			{Name: "OVN_NORTHD_PROBE_INTERVAL", Value: "5000"},
			{Name: "OVN_CONTROLLER_INACTIVITY_PROBE", Value: "180000"},
			{Name: "OVN_NB_INACTIVITY_PROBE", Value: "60000"},
			{Name: "POD_NAME", ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{
					FieldPath: "metadata.name",
				},
			}},

			{Name: "SDN_IMAGE", Value: params.Images.SDN},
			{Name: "KUBE_PROXY_IMAGE", Value: params.Images.KubeProxy},
			{Name: "KUBE_RBAC_PROXY_IMAGE", Value: params.Images.KubeRBACProxy},
			{Name: "MULTUS_IMAGE", Value: params.Images.Multus},
			{Name: "MULTUS_ADMISSION_CONTROLLER_IMAGE", Value: params.Images.MultusAdmissionController},
			{Name: "CNI_PLUGINS_IMAGE", Value: params.Images.CNIPlugins},
			{Name: "BOND_CNI_PLUGIN_IMAGE", Value: params.Images.BondCNIPlugin},
			{Name: "WHEREABOUTS_CNI_IMAGE", Value: params.Images.WhereaboutsCNI},
			{Name: "ROUTE_OVERRRIDE_CNI_IMAGE", Value: params.Images.RouteOverrideCNI},
			{Name: "MULTUS_NETWORKPOLICY_IMAGE", Value: params.Images.MultusNetworkPolicy},
			{Name: "OVN_IMAGE", Value: params.Images.OVN},
			{Name: "EGRESS_ROUTER_CNI_IMAGE", Value: params.Images.EgressRouterCNI},
			{Name: "KURYR_DAEMON_IMAGE", Value: params.Images.KuryrDaemon},
			{Name: "KURYR_CONTROLLER_IMAGE", Value: params.Images.KuryrController},
			{Name: "NETWORK_METRICS_DAEMON_IMAGE", Value: params.Images.NetworkMetricsDaemon},
			{Name: "NETWORK_CHECK_SOURCE_IMAGE", Value: params.Images.NetworkCheckSource},
			{Name: "NETWORK_CHECK_TARGET_IMAGE", Value: params.Images.NetworkCheckTarget},
			{Name: "CLOUD_NETWORK_CONFIG_CONTROLLER_IMAGE", Value: params.Images.CloudNetworkConfigController},
		},
		Name:            operatorName,
		Image:           params.Images.NetworkOperator,
		ImagePullPolicy: corev1.PullAlways, // TODO: Debug purposes only
		Resources: corev1.ResourceRequirements{Requests: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("10m"),
			corev1.ResourceMemory: resource.MustParse("50Mi"),
		}},
		TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
		VolumeMounts: []corev1.VolumeMount{
			{Name: "hosted-etc-kube", MountPath: "/etc/hosted-kubernetes"},
		},
	}}
	dep.Spec.Template.Spec.Volumes = []corev1.Volume{
		{Name: "hosted-etc-kube", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: manifests.KASServiceKubeconfigSecret("").Name}}},
	}

	params.DeploymentConfig.ApplyTo(dep)
	util.AvailabilityProber(kas.InClusterKASReadyURL(dep.Namespace, apiPort), params.AvailabilityProberImage, &dep.Spec.Template.Spec)
}
