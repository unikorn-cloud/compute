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

package cluster

import (
	"context"
	"fmt"
	"maps"
	"net/http"
	"slices"

	"github.com/spjmurray/go-util/pkg/set"

	unikornv1 "github.com/unikorn-cloud/compute/pkg/apis/unikorn/v1alpha1"
	computeprovisioners "github.com/unikorn-cloud/compute/pkg/provisioners"
	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	coreapi "github.com/unikorn-cloud/core/pkg/openapi"
	coreapiutils "github.com/unikorn-cloud/core/pkg/util/api"
	regionapi "github.com/unikorn-cloud/region/pkg/openapi"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/utils/ptr"
)

func (p *Provisioner) reconcileServers(ctx context.Context, client regionapi.ClientWithResponsesInterface, pool *unikornv1.ComputeClusterWorkloadPoolsPoolSpec, servers computeprovisioners.WorkloadPoolProvisionedServerSet, securitygroups computeprovisioners.WorkloadPoolProvisionedSecurityGroupSet, options *computeprovisioners.ClusterOpenstackOptions) error {
	provisionedServers := servers[pool.Name]

	create, update, remove := p.serverReconciliationList(provisionedServers, pool)

	for name := range remove.All() {
		if err := p.deleteServer(ctx, client, provisionedServers[name].Metadata.Id); err != nil {
			return err
		}
	}

	for name := range update.All() {
		// TODO: reconcile changes e.g. security groups.
		p.updateServerStatus(pool, provisionedServers[name])
	}

	for name := range create.All() {
		if err := p.createServer(ctx, client, name, *options.ProviderNetwork.NetworkID, pool, securitygroups[pool.Name]); err != nil {
			return err
		}
	}

	return nil
}

func (p *Provisioner) deleteServer(ctx context.Context, client regionapi.ClientWithResponsesInterface, id string) error {
	resp, err := client.DeleteApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDServersServerIDWithResponse(ctx, p.cluster.Labels[coreconstants.OrganizationLabel], p.cluster.Labels[coreconstants.ProjectLabel], p.cluster.Annotations[coreconstants.IdentityAnnotation], id)
	if err != nil {
		return err
	}

	// Gone already, ignore me!
	if resp.StatusCode() == http.StatusNotFound {
		return nil
	}

	if resp.StatusCode() != http.StatusAccepted {
		return coreapiutils.ExtractError(resp.StatusCode(), resp)
	}

	// TODO: add to the status in a deprovisioning state.
	return nil
}

func (p *Provisioner) convertStatusCondition(in coreapi.ResourceProvisioningStatus) unikornv1core.ConditionReason {
	//nolint:exhaustive
	switch in {
	case coreapi.ResourceProvisioningStatusProvisioning:
		p.resourceProvisioning = true

		return unikornv1core.ConditionReasonProvisioning
	case coreapi.ResourceProvisioningStatusDeprovisioning:
		p.resourceProvisioning = true

		return unikornv1core.ConditionReasonDeprovisioning
	case coreapi.ResourceProvisioningStatusProvisioned:
		return unikornv1core.ConditionReasonProvisioned
	}

	p.resourceProvisioning = true

	return unikornv1core.ConditionReasonErrored
}

func (p *Provisioner) updateServerStatus(pool *unikornv1.ComputeClusterWorkloadPoolsPoolSpec, server regionapi.ServerRead) {
	poolStatus := p.cluster.GetWorkloadPoolStatus(pool.Name)
	poolStatus.Replicas++

	status := unikornv1.MachineStatus{
		Hostname:  server.Metadata.Name,
		PrivateIP: server.Status.PrivateIP,
		PublicIP:  server.Status.PublicIP,
	}

	unikornv1core.UpdateCondition(&status.Conditions, unikornv1core.ConditionAvailable, corev1.ConditionFalse, p.convertStatusCondition(server.Metadata.ProvisioningStatus), "server provisioning")

	poolStatus.Machines = append(poolStatus.Machines, status)
}

func (p *Provisioner) createServer(ctx context.Context, client regionapi.ClientWithResponsesInterface, name, networkID string, pool *unikornv1.ComputeClusterWorkloadPoolsPoolSpec, securitygroup *regionapi.SecurityGroupRead) error {
	publicIPAllocationEnabled := false
	if pool.PublicIPAllocation != nil {
		publicIPAllocationEnabled = pool.PublicIPAllocation.Enabled
	}

	var securitygroups *regionapi.ServerSecurityGroupList
	if securitygroup != nil {
		securitygroups = &regionapi.ServerSecurityGroupList{
			regionapi.ServerSecurityGroup{
				Id: securitygroup.Metadata.Id,
			},
		}
	}

	var userdata *[]byte
	if pool.UserData != nil {
		userdata = &pool.UserData
	}

	request := regionapi.ServerWrite{
		Metadata: coreapi.ResourceWriteMetadata{
			Name:        name,
			Description: ptr.To("Server for cluster " + p.cluster.Name),
			Tags:        p.tags(pool),
		},
		Spec: regionapi.ServerWriteSpec{
			FlavorId: *pool.FlavorID,
			Image: regionapi.ServerImage{
				Id: *pool.ImageID,
			},
			Networks: regionapi.ServerNetworkList{
				regionapi.ServerNetwork{
					Id: networkID,
				},
			},
			PublicIPAllocation: &regionapi.ServerPublicIPAllocation{
				Enabled: publicIPAllocationEnabled,
			},
			SecurityGroups: securitygroups,
			UserData:       userdata,
		},
	}

	resp, err := client.PostApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDServersWithResponse(ctx, p.cluster.Labels[coreconstants.OrganizationLabel], p.cluster.Labels[coreconstants.ProjectLabel], p.cluster.Annotations[coreconstants.IdentityAnnotation], request)
	if err != nil {
		return err
	}

	if resp.StatusCode() != http.StatusCreated {
		return coreapiutils.ExtractError(resp.StatusCode(), resp)
	}

	machine := *resp.JSON201

	p.updateServerStatus(pool, machine)

	return nil
}

func serverName(pool *unikornv1.ComputeClusterWorkloadPoolsPoolSpec, replicaIndex int) string {
	// naive implementation to create a server name based on the pool name and replica index
	return fmt.Sprintf("%s-%d", pool.Name, replicaIndex)
}

// serverReconciliationList compares the provisioned servers with the desired servers and returns the name of the servers to create, reconcile and delete.
func (p *Provisioner) serverReconciliationList(provisioned computeprovisioners.ProvisionedServerSet, desired *unikornv1.ComputeClusterWorkloadPoolsPoolSpec) (set.Set[string], set.Set[string], set.Set[string]) {
	// Things that actually exist...
	actualNames := set.New[string](slices.Collect(maps.Keys(provisioned))...)

	// Things that should exist...
	desiredNames := set.New[string]()

	for i := range *desired.Replicas {
		desiredNames.Add(serverName(desired, i))
	}

	return desiredNames.Difference(actualNames), actualNames.Intersection(desiredNames), actualNames.Difference(desiredNames)
}

func (p *Provisioner) getServers(ctx context.Context, client regionapi.ClientWithResponsesInterface) (*regionapi.ServersResponse, error) {
	response, err := client.GetApiV1OrganizationsOrganizationIDServersWithResponse(ctx, p.cluster.Labels[coreconstants.OrganizationLabel])
	if err != nil {
		return nil, err
	}

	if response.StatusCode() != http.StatusOK {
		return nil, coreapiutils.ExtractError(response.StatusCode(), response)
	}

	// Filter out servers that aren't from this cluster.
	result := slices.DeleteFunc(*response.JSON200, func(server regionapi.ServerRead) bool {
		return p.filterComputeCluster(server.Metadata.Tags)
	})

	return &result, nil
}

func (p *Provisioner) filterComputeCluster(tags *coreapi.TagList) bool {
	if tags == nil {
		return true
	}

	index := slices.IndexFunc(*tags, func(tag coreapi.Tag) bool {
		return tag.Name == coreconstants.ComputeClusterLabel && tag.Value == p.cluster.Name
	})

	return index < 0
}

func (p *Provisioner) getProvisionedServerSet(ctx context.Context, client regionapi.ClientWithResponsesInterface) (computeprovisioners.WorkloadPoolProvisionedServerSet, error) {
	servers, err := p.getServers(ctx, client)
	if err != nil {
		return nil, err
	}

	result := make(computeprovisioners.WorkloadPoolProvisionedServerSet)

	for _, server := range *servers {
		// find the workload pool tag
		index := slices.IndexFunc(*server.Metadata.Tags, func(tag coreapi.Tag) bool {
			return tag.Name == WorkloadPoolLabel
		})

		if index < 0 {
			continue
		}

		poolName := (*server.Metadata.Tags)[index].Value
		if _, exists := result[poolName]; !exists {
			result[poolName] = make(computeprovisioners.ProvisionedServerSet)
		}

		result[poolName][server.Metadata.Name] = server
	}

	return result, nil
}
