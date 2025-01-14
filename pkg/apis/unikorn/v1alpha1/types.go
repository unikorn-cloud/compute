/*
Copyright 2024-2025 the Unikorn Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ComputeWorkloadPoolSpec defines the requested machine pool
// state.
type ComputeWorkloadPoolSpec struct {
	unikornv1core.MachineGeneric `json:",inline"`
	// Name is the name of the pool.
	Name string `json:"name"`
	// PublicIPAllocation is the workload pool public IP allocation configuration.
	PublicIPAllocation *PublicIPAllocationSpec `json:"publicIpAllocation,omitempty"`
	// Firewall is the workload pool firewall configuration.
	Firewall []FirewallRule `json:"firewall,omitempty"`
	// UserData contains configuration information or scripts to use upon launch.
	UserData []byte `json:"userData,omitempty"`
	// ImageSelector is the image selector to use for the pool.
	ImageSelector *ComputeWorkloadPoolImageSelector `json:"imageSelector,omitempty"`
}

type PublicIPAllocationSpec struct {
	// Enabled is a flag to enable public IP allocation.
	Enabled bool `json:"enabled,omitempty"`
}

type ComputeWorkloadPoolImageSelector struct {
	// Distro A distribution name.
	Distro OsDistro `json:"distro"`
	// Variant A free form variant e.g. desktop/server.
	Variant *string `json:"variant,omitempty"`
	// Version of the operating system e.g. "24.04".
	Version string `json:"version"`
}

type OsDistro string

const (
	Rocky  OsDistro = "rocky"
	Ubuntu OsDistro = "ubuntu"
)

// +kubebuilder:validation:Enum=ingress;egress
type FirewallRuleDirection string

const (
	Ingress FirewallRuleDirection = "ingress"
	Egress  FirewallRuleDirection = "egress"
)

// +kubebuilder:validation:Enum=tcp;udp
type FirewallRuleProtocol string

const (
	TCP FirewallRuleProtocol = "tcp"
	UDP FirewallRuleProtocol = "udp"
)

type FirewallRule struct {
	// Direction of traffic flow.
	Direction FirewallRuleDirection `json:"direction"`
	// Protocol The protocol to allow.
	Protocol FirewallRuleProtocol `json:"protocol"`
	// Prefixes is the CIDR block to allow traffic from.
	Prefixes []unikornv1core.IPv4Prefix `json:"cidr"`
	// Port is the port or start of a range of ports.
	Port int `json:"port"`
	// PortMax is the end of a range of ports.
	PortMax *int `json:"portMax,omitempty"`
}

// ComputeClusterList is a typed list of compute clusters.
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type ComputeClusterList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ComputeCluster `json:"items"`
}

// ComputeCluster is an object representing a Compute cluster.
// For now, this is a monolith for simplicity.  In future it may reference
// a provider specific implementation e.g. if CAPI goes out of favour for
// some other new starlet.
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:scope=Namespaced,categories=unikorn
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="display name",type="string",JSONPath=".metadata.labels['unikorn-cloud\\.org/name']"
// +kubebuilder:printcolumn:name="status",type="string",JSONPath=".status.conditions[?(@.type==\"Available\")].reason"
// +kubebuilder:printcolumn:name="age",type="date",JSONPath=".metadata.creationTimestamp"
type ComputeCluster struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              ComputeClusterSpec   `json:"spec"`
	Status            ComputeClusterStatus `json:"status,omitempty"`
}

// ComputeClusterSpec defines the requested state of the Compute cluster.
type ComputeClusterSpec struct {
	// Pause, if true, will inhibit reconciliation.
	Pause bool `json:"pause,omitempty"`
	// Tags are aribrary user data.
	Tags unikornv1core.TagList `json:"tags,omitempty"`
	// Region to provision the cluster in.
	RegionID string `json:"regionId"`
	// Network defines the Compute networking.
	Network *unikornv1core.NetworkGeneric `json:"network"`
	// WorkloadPools defines the workload cluster topology.
	WorkloadPools *ComputeClusterWorkloadPoolsSpec `json:"workloadPools"`
}

type ComputeClusterWorkloadPoolsPoolSpec struct {
	ComputeWorkloadPoolSpec `json:",inline"`
}

type ComputeClusterWorkloadPoolsSpec struct {
	// Pools contains an inline set of pools.  This field will be ignored
	// when Selector is set.  Inline pools are expected to be used for UI
	// generated clusters.
	Pools []ComputeClusterWorkloadPoolsPoolSpec `json:"pools,omitempty"`
}

// ComputeClusterStatus defines the observed state of the Compute cluster.
type ComputeClusterStatus struct {
	// Namespace defines the namespace a cluster resides in.
	Namespace string `json:"namespace,omitempty"`
	// SSHPrivateKey is the key used to access the cluster.
	SSHPrivateKey *string `json:"sshPrivateKey,omitempty"`
	// WorkloadPools is the status of all pools.
	WorkloadPools []WorkloadPoolStatus `json:"workloadpools,omitempty"`
	// Current service state of a Compute cluster.
	Conditions []unikornv1core.Condition `json:"conditions,omitempty"`
}

type WorkloadPoolStatus struct {
	// Name of the workload pool.
	Name string `json:"name"`
	// Replicas that actually exist.
	Replicas int `json:"replicas,omitempty"`
	// Machines in the pool.
	Machines []MachineStatus `json:"machines,omitempty"`
}

type MachineStatus struct {
	// Hostname of the machine.
	Hostname string `json:"hostname"`
	// PrivateIP is the private IP address.
	// TODO: should be IPv4Address.
	PrivateIP *string `json:"privateIp,omitempty"`
	// PublicIP is the public IP address if requested.
	// TODO: should be IPv4Address.
	PublicIP *string `json:"publicIp,omitempty"`
	// Conditions is a set of status conditions for the machine.
	Conditions []unikornv1core.Condition `json:"conditions,omitempty"`
}
