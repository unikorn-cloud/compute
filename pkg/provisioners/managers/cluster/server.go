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

package cluster

import (
	"context"
	"fmt"
	"net/http"
	"slices"

	unikornv1 "github.com/unikorn-cloud/compute/pkg/apis/unikorn/v1alpha1"
	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	coreerrors "github.com/unikorn-cloud/core/pkg/errors"
	coreapi "github.com/unikorn-cloud/core/pkg/openapi"
	regionapi "github.com/unikorn-cloud/region/pkg/openapi"
	"k8s.io/utils/ptr"
)

func (p *Provisioner) reconcileServers(ctx context.Context, client regionapi.ClientWithResponsesInterface, pool *unikornv1.ComputeClusterWorkloadPoolsPoolSpec, networkID *string) error {
	status := p.lookupWorkloadPoolStatus(pool)

	toDelete, toCreate := p.compareServerLists(status.Servers, pool)

	for _, name := range toDelete {
		index := slices.IndexFunc(status.Servers, func(s unikornv1.WorkloadPoolServerStatus) bool {
			return s.Name == name
		})

		if err := p.deleteServer(ctx, client, *status.Servers[index].ProviderID); err != nil {
			return err
		}

		status.Servers = slices.DeleteFunc(status.Servers, func(server unikornv1.WorkloadPoolServerStatus) bool {
			return server.Name == name
		})
	}

	for _, name := range toCreate {
		resp, err := p.createServer(ctx, client, &name, networkID, pool)
		if err != nil {
			return err
		}

		// patch status
		p.patchServerStatus(status, name, &resp.Metadata.Id)
	}

	return nil
}

func (p *Provisioner) patchServerStatus(status *unikornv1.ComputeClusterWorkloadPoolStatus, serverName string, providerID *string) {
	index := slices.IndexFunc(status.Servers, func(ss unikornv1.WorkloadPoolServerStatus) bool {
		return ss.Name == serverName
	})

	if index >= 0 {
		status.Servers[index].ProviderID = providerID
		return
	}

	status.Servers = append(status.Servers, unikornv1.WorkloadPoolServerStatus{
		Name:       serverName,
		ProviderID: providerID,
	})
}

func (p *Provisioner) deleteServer(ctx context.Context, client regionapi.ClientWithResponsesInterface, id string) error {
	resp, err := client.DeleteApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDServersServerIDWithResponse(ctx, p.cluster.Labels[coreconstants.OrganizationLabel], p.cluster.Labels[coreconstants.ProjectLabel], p.cluster.Annotations[coreconstants.IdentityAnnotation], id)
	if err != nil {
		return err
	}

	if resp.StatusCode() != http.StatusAccepted && resp.StatusCode() != http.StatusNotFound {
		return fmt.Errorf("%w: server DELETE expected 202 got %d", coreerrors.ErrAPIStatus, resp.StatusCode())
	}

	return nil
}

func (p *Provisioner) createServer(ctx context.Context, client regionapi.ClientWithResponsesInterface, name, networkID *string, pool *unikornv1.ComputeClusterWorkloadPoolsPoolSpec) (*regionapi.ServerRead, error) {
	firewall := p.lookupWorkloadPoolFirewallStatus(pool)

	publicIPAllocationEnabled := false
	if pool.PublicIPAllocation != nil {
		publicIPAllocationEnabled = pool.PublicIPAllocation.Enabled
	}

	var securitygroups *regionapi.ServerSecurityGroupList
	if firewall != nil && firewall.ProviderID != nil {
		securitygroups = &regionapi.ServerSecurityGroupList{
			regionapi.ServerSecurityGroup{
				Id: *firewall.ProviderID,
			},
		}
	}

	request := regionapi.ServerWrite{
		Metadata: coreapi.ResourceWriteMetadata{
			Name:        *name,
			Description: ptr.To("Server for cluster " + p.cluster.Name),
		},
		Spec: regionapi.ServerWriteSpec{
			Tags:     p.tags(pool),
			FlavorId: *pool.FlavorID,
			Image: regionapi.ServerImage{
				Id: pool.ImageID,
			},
			Networks: regionapi.ServerNetworkList{
				regionapi.ServerNetwork{
					Id: *networkID,
				},
			},
			PublicIPAllocation: &regionapi.ServerPublicIPAllocation{
				Enabled: publicIPAllocationEnabled,
			},
			SecurityGroups: securitygroups,
		},
	}

	resp, err := client.PostApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDServersWithResponse(
		ctx, p.cluster.Labels[coreconstants.OrganizationLabel], p.cluster.Labels[coreconstants.ProjectLabel], p.cluster.Annotations[coreconstants.IdentityAnnotation], request)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode() != http.StatusCreated {
		return nil, fmt.Errorf("%w: server POST expected 201 got %d", coreerrors.ErrAPIStatus, resp.StatusCode())
	}

	return resp.JSON201, nil
}

func (p *Provisioner) serverName(pool *unikornv1.ComputeClusterWorkloadPoolsPoolSpec, replicaIndex int) string {
	// naive implementation to create a server name based on the pool name and replica index
	return fmt.Sprintf("%s-%d", pool.Name, replicaIndex)
}

func (p *Provisioner) compareServerLists(provisioned []unikornv1.WorkloadPoolServerStatus, desired *unikornv1.ComputeClusterWorkloadPoolsPoolSpec) (toDelete, toCreate []string) {
	provisionedSet := make(map[string]struct{})
	desiredSet := make(map[string]struct{})

	// populate sets
	for _, server := range provisioned {
		if server.ProviderID != nil {
			provisionedSet[server.Name] = struct{}{}
		}
	}

	for i := 0; i < *desired.Replicas; i++ {
		desiredSet[p.serverName(desired, i)] = struct{}{}
	}

	// find rules to delete
	for id := range provisionedSet {
		if _, exists := desiredSet[id]; !exists {
			toDelete = append(toDelete, id)
		}
	}

	// find rules to create
	for id := range desiredSet {
		if _, exists := provisionedSet[id]; !exists {
			toCreate = append(toCreate, id)
		}
	}

	return toDelete, toCreate
}
