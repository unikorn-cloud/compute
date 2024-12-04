/*
Copyright 2024 the Unikorn Authors.

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
	Firewall *FirewallSpec `json:"firewall,omitempty"`
	// UserData contains configuration information or scripts to use upon launch.
	UserData []byte `json:"userData,omitempty"`
}

type PublicIPAllocationSpec struct {
	// Enabled is a flag to enable public IP allocation.
	Enabled bool `json:"enabled,omitempty"`
}

type FirewallSpec struct {
	// Ingress is a list of firewall rules applied to a workload pool.
	Ingress []FirewallRule `json:"ingress,omitempty"`
}

type FirewallRule struct {
	// ID is the firewall rule identifier.
	ID string `json:"id,omitempty"`
	// Protocol The protocol to allow.
	Protocol FirewallRuleProtocol `json:"protocol"`
	// CIDR is the CIDR block to allow traffic from.
	CIDR unikornv1core.IPv4Prefix `json:"cidr"`
	// Port is the port or range of ports.
	Port FirewallRulePort `json:"port"`
}

// +kubebuilder:validation:Enum=tcp;udp
type FirewallRuleProtocol string

const (
	TCP FirewallRuleProtocol = "tcp"
	UDP FirewallRuleProtocol = "udp"
)

// +kubebuilder:validation:XValidation:message="at least one of number or range must be defined",rule=(has(self.number) || has(self.range))
type FirewallRulePort struct {
	// Number is the port number.
	Number *int `json:"number,omitempty"`
	// Range is the port range.
	Range *FirewallRulePortRange `json:"range,omitempty"`
}

type FirewallRulePortRange struct {
	// Start is the start of the range.
	// +kubebuilder:validation:Minimum=1
	Start int `json:"start"`
	// End is the end of the range.
	// +kubebuilder:validation:Maximum=65535
	End int `json:"end"`
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
	// Current service state of a Compute cluster.
	Conditions []unikornv1core.Condition `json:"conditions,omitempty"`
}
