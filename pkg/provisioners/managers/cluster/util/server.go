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

package util

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	unikornv1 "github.com/unikorn-cloud/compute/pkg/apis/unikorn/v1alpha1"
	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	coreapi "github.com/unikorn-cloud/core/pkg/openapi"
	regionapi "github.com/unikorn-cloud/region/pkg/openapi"

	corev1 "k8s.io/api/core/v1"
)

var (
	ErrConsistency = errors.New("consistency error")
)

const (
	// WorkloadPoolLabel is the label key for the workload pool.
	WorkloadPoolLabel = "unikorn-cloud.org/workloadpool"
)

// ClusterTagSelector allows us to select only servers for a specific cluster.
func ClusterTagSelector(cluster *unikornv1.ComputeCluster) *coreapi.TagSelectorParameter {
	tags := coreapi.TagSelectorParameter{
		coreconstants.ComputeClusterLabel + "=" + cluster.Name,
	}

	return &tags
}

// GetWorkloadPoolTag derives the pool from the API resource.
func GetWorkloadPoolTag(tags *coreapi.TagList) (string, error) {
	if tags == nil {
		return "", fmt.Errorf("%w: workload pool tags missing", ErrConsistency)
	}

	t := *tags

	isWorkloadPoolTag := func(tag coreapi.Tag) bool {
		return tag.Name == WorkloadPoolLabel
	}

	index := slices.IndexFunc(t, isWorkloadPoolTag)
	if index < 0 {
		return "", fmt.Errorf("%w: workload pool tag missing", ErrConsistency)
	}

	return t[index].Value, nil
}

// ConvertProvisioningStatusCondition converts from an OpenAPI status condition into a Kubernetes one.
func ConvertProvisioningStatusCondition(in coreapi.ResourceProvisioningStatus) (corev1.ConditionStatus, unikornv1core.ConditionReason, string) {
	//nolint:exhaustive
	switch in {
	case coreapi.ResourceProvisioningStatusProvisioning:
		return corev1.ConditionFalse, unikornv1core.ConditionReasonProvisioning, "provisioning"
	case coreapi.ResourceProvisioningStatusDeprovisioning:
		return corev1.ConditionFalse, unikornv1core.ConditionReasonDeprovisioning, "deprovisioning"
	case coreapi.ResourceProvisioningStatusProvisioned:
		return corev1.ConditionTrue, unikornv1core.ConditionReasonProvisioned, "provisioned"
	case coreapi.ResourceProvisioningStatusError:
		return corev1.ConditionFalse, unikornv1core.ConditionReasonErrored, "provisioning error"
	}

	return corev1.ConditionFalse, unikornv1core.ConditionReasonUnknown, "provisioning unknown"
}

// ConvertHealthStatusCondition converts from an OpenAPI status condition into a Kubernetes one.
func ConvertHealthStatusCondition(in coreapi.ResourceHealthStatus) (corev1.ConditionStatus, unikornv1core.ConditionReason, string) {
	//nolint:exhaustive
	switch in {
	case coreapi.ResourceHealthStatusHealthy:
		return corev1.ConditionTrue, unikornv1core.ConditionReasonHealthy, "healthy"
	case coreapi.ResourceHealthStatusDegraded:
		return corev1.ConditionFalse, unikornv1core.ConditionReasonDegraded, "degraded"
	case coreapi.ResourceHealthStatusError:
		return corev1.ConditionFalse, unikornv1core.ConditionReasonErrored, "error"
	}

	return corev1.ConditionFalse, unikornv1core.ConditionReasonUnknown, "health unknown"
}

// UpdateServerStatus adds a server to the cluster's status.
// The boolean returned indicates whether the service is successfully provisioned or not.
func UpdateServerStatus(cluster *unikornv1.ComputeCluster, server *regionapi.ServerRead) (bool, error) {
	poolName, err := GetWorkloadPoolTag(server.Metadata.Tags)
	if err != nil {
		return false, err
	}

	poolStatus := cluster.GetWorkloadPoolStatus(poolName)
	poolStatus.Replicas++

	status := unikornv1.MachineStatus{
		Hostname:  server.Metadata.Name,
		FlavorID:  server.Spec.FlavorId,
		ImageID:   server.Spec.ImageId,
		PrivateIP: server.Status.PrivateIP,
		PublicIP:  server.Status.PublicIP,
	}

	provisioningStatus, provisioningReason, provisioningMessage := ConvertProvisioningStatusCondition(server.Metadata.ProvisioningStatus)
	healthStatus, healthReason, healthMessage := ConvertHealthStatusCondition(server.Metadata.HealthStatus)

	unikornv1core.UpdateCondition(&status.Conditions, unikornv1core.ConditionAvailable, provisioningStatus, provisioningReason, provisioningMessage)
	unikornv1core.UpdateCondition(&status.Conditions, unikornv1core.ConditionHealthy, healthStatus, healthReason, healthMessage)

	poolStatus.Machines = append(poolStatus.Machines, status)

	return provisioningStatus == corev1.ConditionTrue, nil
}

// EveryFunc returns if every element is true.  I'm quite frankly amazed
// this isn't in the standard library.
func EveryFunc[S ~[]E, E any](s S, f func(E) bool) bool {
	for i := range s {
		if !f(s[i]) {
			return false
		}
	}

	return true
}

// serverHealthStatusMatch generates a function that tells us if the server health
// status matches what we expect.
func serverHealthStatusMatch(status coreapi.ResourceHealthStatus) func(regionapi.ServerRead) bool {
	return func(s regionapi.ServerRead) bool {
		return s.Metadata.HealthStatus == status
	}
}

// UpdateClusterStatus updates the cluster status.  Mostly... as this is shared
// with the provisioner and the monitor.
func UpdateClusterStatus(cluster *unikornv1.ComputeCluster, servers regionapi.ServersRead) (bool, error) {
	allServersProvisioned := true

	// Update the workload pool statuses.
	cluster.Status.WorkloadPools = nil

	for i := range servers {
		ok, err := UpdateServerStatus(cluster, &servers[i])
		if err != nil {
			return false, err
		}

		allServersProvisioned = allServersProvisioned && ok
	}

	slices.SortFunc(cluster.Status.WorkloadPools, func(a, b unikornv1.WorkloadPoolStatus) int {
		return strings.Compare(a.Name, b.Name)
	})

	for _, pool := range cluster.Status.WorkloadPools {
		slices.SortFunc(pool.Machines, func(a, b unikornv1.MachineStatus) int {
			return strings.Compare(a.Hostname, b.Hostname)
		})
	}

	// Update the overall health status.
	// Overall status, if all servers are healthy/unknown/error, then assume that state overall
	// otherwise we're degraded.
	healthStatus := coreapi.ResourceHealthStatusDegraded

	switch {
	case EveryFunc(servers, serverHealthStatusMatch(coreapi.ResourceHealthStatusHealthy)):
		healthStatus = coreapi.ResourceHealthStatusHealthy
	case EveryFunc(servers, serverHealthStatusMatch(coreapi.ResourceHealthStatusError)):
		healthStatus = coreapi.ResourceHealthStatusError
	case EveryFunc(servers, serverHealthStatusMatch(coreapi.ResourceHealthStatusUnknown)):
		healthStatus = coreapi.ResourceHealthStatusUnknown
	}

	status, reason, message := ConvertHealthStatusCondition(healthStatus)

	unikornv1core.UpdateCondition(&cluster.Status.Conditions, unikornv1core.ConditionHealthy, status, reason, message)

	return allServersProvisioned, nil
}
