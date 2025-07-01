/*
Copyright 2025 the Unikorn Authors.

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

	"github.com/unikorn-cloud/compute/pkg/constants"
	"github.com/unikorn-cloud/compute/pkg/provisioners/managers/cluster/util"
	coreclient "github.com/unikorn-cloud/core/pkg/client"
	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	coreapi "github.com/unikorn-cloud/core/pkg/openapi"
	"github.com/unikorn-cloud/core/pkg/provisioners"
	coreapiutils "github.com/unikorn-cloud/core/pkg/util/api"
	identityclient "github.com/unikorn-cloud/identity/pkg/client"
	regionclient "github.com/unikorn-cloud/region/pkg/client"
	regionapi "github.com/unikorn-cloud/region/pkg/openapi"

	"sigs.k8s.io/controller-runtime/pkg/log"
)

// getRegionClient returns an authenticated client.
// TODO: the client should be cached for an appropriate period to avoid polluting the
// caches in identity with new tokens during busy periods.
func (p *Provisioner) getRegionClient(ctx context.Context, traceName string) (regionapi.ClientWithResponsesInterface, error) {
	cli, err := coreclient.ProvisionerClientFromContext(ctx)
	if err != nil {
		return nil, err
	}

	tokenIssuer := identityclient.NewTokenIssuer(cli, p.options.identityOptions, &p.options.clientOptions, constants.Application, constants.Version)

	token, err := tokenIssuer.Issue(ctx, traceName)
	if err != nil {
		return nil, err
	}

	getter := regionclient.New(cli, p.options.regionOptions, &p.options.clientOptions)

	client, err := getter.ControllerClient(ctx, token, &p.cluster)
	if err != nil {
		return nil, err
	}

	return client, nil
}

// getIdentity returns the cloud identity associated with a cluster.
func (p *Provisioner) getIdentity(ctx context.Context, client regionapi.ClientWithResponsesInterface) (*regionapi.IdentityRead, error) {
	log := log.FromContext(ctx)

	response, err := client.GetApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDWithResponse(ctx, p.cluster.Labels[coreconstants.OrganizationLabel], p.cluster.Labels[coreconstants.ProjectLabel], p.cluster.Annotations[coreconstants.IdentityAnnotation])
	if err != nil {
		return nil, err
	}

	if response.StatusCode() != http.StatusOK {
		return nil, coreapiutils.ExtractError(response.StatusCode(), response)
	}

	resource := response.JSON200

	//nolint:exhaustive
	switch resource.Metadata.ProvisioningStatus {
	case coreapi.ResourceProvisioningStatusProvisioned:
		return resource, nil
	case coreapi.ResourceProvisioningStatusUnknown, coreapi.ResourceProvisioningStatusProvisioning:
		log.Info("waiting for identity to become ready")

		return nil, provisioners.ErrYield
	}

	return nil, fmt.Errorf("%w: unhandled status %s", ErrResourceDependency, resource.Metadata.ProvisioningStatus)
}

// deleteIdentity deletes an identity associated with a cluster.
func (p *Provisioner) deleteIdentity(ctx context.Context, client regionapi.ClientWithResponsesInterface) error {
	response, err := client.DeleteApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDWithResponse(ctx, p.cluster.Labels[coreconstants.OrganizationLabel], p.cluster.Labels[coreconstants.ProjectLabel], p.cluster.Annotations[coreconstants.IdentityAnnotation])
	if err != nil {
		return err
	}

	statusCode := response.StatusCode()

	// An accepted status means the API has recorded the deletion event and
	// we can delete the cluster, a not found means it's been deleted already
	// and again can proceed.  The goal here is not to leak resources.
	if statusCode != http.StatusAccepted && statusCode != http.StatusNotFound {
		return coreapiutils.ExtractError(statusCode, response)
	}

	return nil
}

// getNetwork returns the network associated with a compute cluster.
func (p *Provisioner) getNetwork(ctx context.Context, client regionapi.ClientWithResponsesInterface) (*regionapi.NetworkRead, error) {
	log := log.FromContext(ctx)

	networkID, ok := p.cluster.Annotations[coreconstants.PhysicalNetworkAnnotation]
	if !ok {
		//nolint: nilnil
		return nil, nil
	}

	response, err := client.GetApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDNetworksNetworkIDWithResponse(ctx, p.cluster.Labels[coreconstants.OrganizationLabel], p.cluster.Labels[coreconstants.ProjectLabel], p.cluster.Annotations[coreconstants.IdentityAnnotation], networkID)
	if err != nil {
		return nil, err
	}

	if response.StatusCode() != http.StatusOK {
		return nil, coreapiutils.ExtractError(response.StatusCode(), response)
	}

	resource := response.JSON200

	//nolint:exhaustive
	switch resource.Metadata.ProvisioningStatus {
	case coreapi.ResourceProvisioningStatusProvisioned:
		return resource, nil
	case coreapi.ResourceProvisioningStatusUnknown, coreapi.ResourceProvisioningStatusProvisioning:
		log.Info("waiting for network to become ready")

		return nil, provisioners.ErrYield
	}

	return nil, fmt.Errorf("%w: unhandled status %s", ErrResourceDependency, resource.Metadata.ProvisioningStatus)
}

// listServers lists all servers that are part of this cluster.
func (p *Provisioner) listServers(ctx context.Context, client regionapi.ClientWithResponsesInterface) (regionapi.ServersResponse, error) {
	params := &regionapi.GetApiV1OrganizationsOrganizationIDServersParams{
		Tag: util.ClusterTagSelector(&p.cluster),
	}

	response, err := client.GetApiV1OrganizationsOrganizationIDServersWithResponse(ctx, p.cluster.Labels[coreconstants.OrganizationLabel], params)
	if err != nil {
		return nil, err
	}

	if response.StatusCode() != http.StatusOK {
		return nil, coreapiutils.ExtractError(response.StatusCode(), response)
	}

	return *response.JSON200, nil
}

// createServer creates a new server.
func (p *Provisioner) createServer(ctx context.Context, client regionapi.ClientWithResponsesInterface, request *regionapi.ServerWrite) (*regionapi.ServerResponse, error) {
	resp, err := client.PostApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDServersWithResponse(ctx, p.cluster.Labels[coreconstants.OrganizationLabel], p.cluster.Labels[coreconstants.ProjectLabel], p.cluster.Annotations[coreconstants.IdentityAnnotation], *request)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode() != http.StatusCreated {
		return nil, coreapiutils.ExtractError(resp.StatusCode(), resp)
	}

	return resp.JSON201, nil
}

// updateServer updates a server.
func (p *Provisioner) updateServer(ctx context.Context, client regionapi.ClientWithResponsesInterface, serverID string, request *regionapi.ServerWrite) (*regionapi.ServerResponse, error) {
	resp, err := client.PutApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDServersServerIDWithResponse(ctx, p.cluster.Labels[coreconstants.OrganizationLabel], p.cluster.Labels[coreconstants.ProjectLabel], p.cluster.Annotations[coreconstants.IdentityAnnotation], serverID, *request)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode() != http.StatusAccepted {
		return nil, coreapiutils.ExtractError(resp.StatusCode(), resp)
	}

	return resp.JSON202, nil
}

// deleteServer deletes a server.
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

// listSecurityGroups reads all security groups for the cluster.
func (p *Provisioner) listSecurityGroups(ctx context.Context, client regionapi.ClientWithResponsesInterface) (regionapi.SecurityGroupsResponse, error) {
	params := &regionapi.GetApiV1OrganizationsOrganizationIDSecuritygroupsParams{
		Tag: util.ClusterTagSelector(&p.cluster),
	}

	response, err := client.GetApiV1OrganizationsOrganizationIDSecuritygroupsWithResponse(ctx, p.cluster.Labels[coreconstants.OrganizationLabel], params)
	if err != nil {
		return nil, err
	}

	if response.StatusCode() != http.StatusOK {
		return nil, coreapiutils.ExtractError(response.StatusCode(), response)
	}

	return *response.JSON200, nil
}

// createSecurityGroup creates a security group.
func (p *Provisioner) createSecurityGroup(ctx context.Context, client regionapi.ClientWithResponsesInterface, request *regionapi.SecurityGroupWrite) (*regionapi.SecurityGroupRead, error) {
	resp, err := client.PostApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDSecuritygroupsWithResponse(ctx, p.cluster.Labels[coreconstants.OrganizationLabel], p.cluster.Labels[coreconstants.ProjectLabel], p.cluster.Annotations[coreconstants.IdentityAnnotation], *request)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode() != http.StatusCreated {
		return nil, coreapiutils.ExtractError(resp.StatusCode(), resp)
	}

	return resp.JSON201, nil
}

// deleteSecurityGroup delete's a security group.
func (p *Provisioner) deleteSecurityGroup(ctx context.Context, client regionapi.ClientWithResponsesInterface, id string) error {
	resp, err := client.DeleteApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDSecuritygroupsSecurityGroupIDWithResponse(ctx, p.cluster.Labels[coreconstants.OrganizationLabel], p.cluster.Labels[coreconstants.ProjectLabel], p.cluster.Annotations[coreconstants.IdentityAnnotation], id)
	if err != nil {
		return err
	}

	if resp.StatusCode() != http.StatusAccepted && resp.StatusCode() != http.StatusNotFound {
		return coreapiutils.ExtractError(resp.StatusCode(), resp)
	}

	return nil
}

// listSecurityGroupRules lists all security group rules for a security group.
func (p *Provisioner) listSecurityGroupRules(ctx context.Context, client regionapi.ClientWithResponsesInterface, securityGroupID string) (regionapi.SecurityGroupRulesRead, error) {
	response, err := client.GetApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDSecuritygroupsSecurityGroupIDRulesWithResponse(ctx, p.cluster.Labels[coreconstants.OrganizationLabel], p.cluster.Labels[coreconstants.ProjectLabel], p.cluster.Annotations[coreconstants.IdentityAnnotation], securityGroupID)
	if err != nil {
		return nil, err
	}

	if response.StatusCode() != http.StatusOK {
		return nil, coreapiutils.ExtractError(response.StatusCode(), response)
	}

	return *response.JSON200, nil
}

// createSecurityGroupRule creates a security group rule.
func (p *Provisioner) createSecurityGroupRule(ctx context.Context, client regionapi.ClientWithResponsesInterface, securityGroupID string, request *regionapi.SecurityGroupRuleWrite) (*regionapi.SecurityGroupRuleRead, error) {
	resp, err := client.PostApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDSecuritygroupsSecurityGroupIDRulesWithResponse(ctx, p.cluster.Labels[coreconstants.OrganizationLabel], p.cluster.Labels[coreconstants.ProjectLabel], p.cluster.Annotations[coreconstants.IdentityAnnotation], securityGroupID, *request)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode() != http.StatusCreated {
		return nil, coreapiutils.ExtractError(resp.StatusCode(), resp)
	}

	return resp.JSON201, nil
}

// deleteSecurityGroupRule deletes a security group rule.
func (p *Provisioner) deleteSecurityGroupRule(ctx context.Context, client regionapi.ClientWithResponsesInterface, securityGroupID, ruleID string) error {
	resp, err := client.DeleteApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDSecuritygroupsSecurityGroupIDRulesRuleIDWithResponse(ctx, p.cluster.Labels[coreconstants.OrganizationLabel], p.cluster.Labels[coreconstants.ProjectLabel], p.cluster.Annotations[coreconstants.IdentityAnnotation], securityGroupID, ruleID)
	if err != nil {
		return err
	}

	if resp.StatusCode() != http.StatusAccepted && resp.StatusCode() != http.StatusNotFound {
		return coreapiutils.ExtractError(resp.StatusCode(), resp)
	}

	return nil
}
