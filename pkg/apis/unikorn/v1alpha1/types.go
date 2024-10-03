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
