// Package openapi provides primitives to interact with the openapi HTTP API.
//
// Code generated by github.com/oapi-codegen/oapi-codegen/v2 version v2.4.1 DO NOT EDIT.
package openapi

import (
	externalRef0 "github.com/unikorn-cloud/core/pkg/openapi"
	externalRef1 "github.com/unikorn-cloud/region/pkg/openapi"
)

const (
	Oauth2AuthenticationScopes = "oauth2Authentication.Scopes"
)

// Defines values for FirewallRuleProtocol.
const (
	Tcp FirewallRuleProtocol = "tcp"
	Udp FirewallRuleProtocol = "udp"
)

// ComputeClusterMachineStatus Compute cluster machine status.
type ComputeClusterMachineStatus struct {
	// Hostname Machine hostname.
	Hostname string `json:"hostname"`

	// PrivateIP Machine private IP address.
	PrivateIP *string `json:"privateIP,omitempty"`

	// PublicIP Machine public IP address.
	PublicIP *string `json:"publicIP,omitempty"`

	// Status The provisioning state of a resource.
	Status externalRef0.ResourceProvisioningStatus `json:"status"`
}

// ComputeClusterMachinesStatus A list of Compute cluster machines status.
type ComputeClusterMachinesStatus = []ComputeClusterMachineStatus

// ComputeClusterRead Compute cluster read.
type ComputeClusterRead struct {
	Metadata externalRef0.ProjectScopedResourceReadMetadata `json:"metadata"`

	// Spec Compute cluster creation parameters.
	Spec ComputeClusterSpec `json:"spec"`

	// Status Compute cluster status.
	Status *ComputeClusterStatus `json:"status,omitempty"`
}

// ComputeClusterSpec Compute cluster creation parameters.
type ComputeClusterSpec struct {
	// RegionId The region to provision the cluster in.
	RegionId string `json:"regionId"`

	// WorkloadPools A list of Compute cluster workload pools.
	WorkloadPools ComputeClusterWorkloadPools `json:"workloadPools"`
}

// ComputeClusterStatus Compute cluster status.
type ComputeClusterStatus struct {
	// WorkloadPools A list of Compute cluster workload pools status.
	WorkloadPools *ComputeClusterWorkloadPoolsStatus `json:"workloadPools,omitempty"`
}

// ComputeClusterWorkloadPool A Compute cluster workload pool.
type ComputeClusterWorkloadPool struct {
	// Machine A Compute cluster machine.
	Machine MachinePool `json:"machine"`

	// Name Workload pool name.
	Name string `json:"name"`
}

// ComputeClusterWorkloadPoolStatus Compute cluster workload pool status.
type ComputeClusterWorkloadPoolStatus struct {
	// Machines A list of Compute cluster machines status.
	Machines *ComputeClusterMachinesStatus `json:"machines,omitempty"`

	// Name Workload pool name.
	Name string `json:"name"`

	// Replicas Number of machines.
	Replicas int `json:"replicas"`
}

// ComputeClusterWorkloadPools A list of Compute cluster workload pools.
type ComputeClusterWorkloadPools = []ComputeClusterWorkloadPool

// ComputeClusterWorkloadPoolsStatus A list of Compute cluster workload pools status.
type ComputeClusterWorkloadPoolsStatus = []ComputeClusterWorkloadPoolStatus

// ComputeClusterWrite Compute cluster create or update.
type ComputeClusterWrite struct {
	// Metadata Resource metadata valid for all API resource reads and writes.
	Metadata externalRef0.ResourceWriteMetadata `json:"metadata"`

	// Spec Compute cluster creation parameters.
	Spec ComputeClusterSpec `json:"spec"`
}

// ComputeClusters A list of Compute clusters.
type ComputeClusters = []ComputeClusterRead

// Firewall A list of firewall rules applied to a workload pool.
type Firewall struct {
	// Ingress A list of firewall rules applied to a workload pool.
	Ingress *FirewallRules `json:"ingress,omitempty"`
}

// FirewallRule A firewall rule applied to a workload pool.
type FirewallRule struct {
	// Cidr A list of CIDR blocks to allow, it might be any IPv4 or IPv6 in CIDR notation.
	Cidr []string `json:"cidr"`

	// Port The port definition to allow traffic.
	Port FirewallRulePort `json:"port"`

	// Protocol The protocol to allow.
	Protocol FirewallRuleProtocol `json:"protocol"`
}

// FirewallRuleProtocol The protocol to allow.
type FirewallRuleProtocol string

// FirewallRulePort The port definition to allow traffic.
type FirewallRulePort struct {
	// Number The port to allow.
	Number *int `json:"number,omitempty"`

	// Range The port range to allow traffic.
	Range *FirewallRulePortRange `json:"range,omitempty"`
}

// FirewallRulePortRange The port range to allow traffic.
type FirewallRulePortRange struct {
	// End The end of the port range.
	End int `json:"end"`

	// Start The start of the port range.
	Start int `json:"start"`
}

// FirewallRules A list of firewall rules applied to a workload pool.
type FirewallRules = []FirewallRule

// ImageSelector A server image selector.
type ImageSelector struct {
	// Distro A distribution name.
	Distro externalRef1.OsDistro `json:"distro"`

	// Variant The operating system variant.
	Variant *string `json:"variant,omitempty"`

	// Version The operating system version to use, if not defined it will use the latest.
	Version *string `json:"version,omitempty"`
}

// KubernetesNameParameter A Compute name. Must be a valid DNS containing only lower case characters, numbers or hyphens, start and end with a character or number, and be at most 63 characters in length.
type KubernetesNameParameter = string

// MachinePool A Compute cluster machine.
type MachinePool struct {
	// Disk A volume.
	Disk *Volume `json:"disk,omitempty"`

	// Firewall A list of firewall rules applied to a workload pool.
	Firewall *Firewall `json:"firewall,omitempty"`

	// FlavorId Flavor ID.
	FlavorId string `json:"flavorId"`

	// Image A server image selector.
	Image ImageSelector `json:"image"`

	// PublicIPAllocation A public IP allocation settings.
	PublicIPAllocation *PublicIPAllocation `json:"publicIPAllocation,omitempty"`

	// Replicas Number of machines for a statically sized pool or the maximum for an auto-scaled pool.
	Replicas int `json:"replicas"`

	// UserData UserData contains base64-encoded configuration information or scripts to use upon launch.
	UserData *[]byte `json:"userData,omitempty"`
}

// PublicIPAllocation A public IP allocation settings.
type PublicIPAllocation struct {
	// Enabled Enable public IP allocation.
	Enabled bool `json:"enabled"`
}

// Volume A volume.
type Volume struct {
	// Size Disk size in GiB.
	Size int `json:"size"`
}

// ClusterIDParameter A Compute name. Must be a valid DNS containing only lower case characters, numbers or hyphens, start and end with a character or number, and be at most 63 characters in length.
type ClusterIDParameter = KubernetesNameParameter

// OrganizationIDParameter A Compute name. Must be a valid DNS containing only lower case characters, numbers or hyphens, start and end with a character or number, and be at most 63 characters in length.
type OrganizationIDParameter = KubernetesNameParameter

// ProjectIDParameter A Compute name. Must be a valid DNS containing only lower case characters, numbers or hyphens, start and end with a character or number, and be at most 63 characters in length.
type ProjectIDParameter = KubernetesNameParameter

// RegionIDParameter A Compute name. Must be a valid DNS containing only lower case characters, numbers or hyphens, start and end with a character or number, and be at most 63 characters in length.
type RegionIDParameter = KubernetesNameParameter

// ComputeClusterResponse Compute cluster read.
type ComputeClusterResponse = ComputeClusterRead

// ComputeClustersResponse A list of Compute clusters.
type ComputeClustersResponse = ComputeClusters

// CreateComputeClusterRequest Compute cluster create or update.
type CreateComputeClusterRequest = ComputeClusterWrite

// PostApiV1OrganizationsOrganizationIDProjectsProjectIDClustersJSONRequestBody defines body for PostApiV1OrganizationsOrganizationIDProjectsProjectIDClusters for application/json ContentType.
type PostApiV1OrganizationsOrganizationIDProjectsProjectIDClustersJSONRequestBody = ComputeClusterWrite

// PutApiV1OrganizationsOrganizationIDProjectsProjectIDClustersClusterIDJSONRequestBody defines body for PutApiV1OrganizationsOrganizationIDProjectsProjectIDClustersClusterID for application/json ContentType.
type PutApiV1OrganizationsOrganizationIDProjectsProjectIDClustersClusterIDJSONRequestBody = ComputeClusterWrite
