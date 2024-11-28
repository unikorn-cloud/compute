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
	computeprovisioners "github.com/unikorn-cloud/compute/pkg/provisioners"
	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	coreerrors "github.com/unikorn-cloud/core/pkg/errors"
	coreapi "github.com/unikorn-cloud/core/pkg/openapi"
	"github.com/unikorn-cloud/core/pkg/provisioners"
	regionapi "github.com/unikorn-cloud/region/pkg/openapi"
	"k8s.io/utils/ptr"
)

func (p *Provisioner) reconcileSecurityGroup(ctx context.Context, client regionapi.ClientWithResponsesInterface, pool *unikornv1.ComputeClusterWorkloadPoolsPoolSpec, securitygroups computeprovisioners.WorkloadPoolProvisionedSecurityGroupSet) error {
	provisionedSecurityGroup := securitygroups[pool.Name]

	if provisionedSecurityGroup == nil && pool.Firewall == nil {
		// nothing to do
		return nil
	}

	if provisionedSecurityGroup != nil && pool.Firewall == nil {
		if err := p.deleteSecurityGroup(ctx, client, provisionedSecurityGroup.Metadata.Id); err != nil {
			return err
		}

		return nil
	}

	if provisionedSecurityGroup == nil && pool.Firewall != nil {
		if err := p.createSecurityGroup(ctx, client, pool); err != nil {
			return err
		}

		// wait until security group is created before creating rules and servers
		return provisioners.ErrYield
	}

	if err := p.reconcileSecurityGroupRules(ctx, client, pool, provisionedSecurityGroup); err != nil {
		return err
	}

	return nil
}

func (p *Provisioner) reconcileSecurityGroupRules(ctx context.Context, client regionapi.ClientWithResponsesInterface, pool *unikornv1.ComputeClusterWorkloadPoolsPoolSpec, securitygroup *regionapi.SecurityGroupRead) error {
	if securitygroup == nil {
		// wait until security group is created
		return provisioners.ErrYield
	}

	provisionedRules, err := p.getSecurityGroupRules(ctx, client, securitygroup.Metadata.Id)
	if err != nil {
		return err
	}

	toDelete, toCreate := p.compareFirewallRuleLists(provisionedRules, pool.Firewall.Ingress)

	for _, id := range toDelete {
		index := slices.IndexFunc(provisionedRules, func(rule regionapi.SecurityGroupRuleRead) bool {
			return rule.Metadata.Name == id
		})

		if err := p.deleteSecurityGroupRule(ctx, client, securitygroup.Metadata.Id, (provisionedRules)[index].Metadata.Id); err != nil {
			return err
		}
	}

	for _, id := range toCreate {
		index := slices.IndexFunc(pool.Firewall.Ingress, func(rule unikornv1.FirewallRule) bool {
			return rule.ID == id
		})

		if err := p.createSecurityGroupRule(ctx, client, pool, securitygroup.Metadata.Id, &pool.Firewall.Ingress[index]); err != nil {
			return err
		}
	}

	return nil
}

func (p *Provisioner) createSecurityGroup(ctx context.Context, client regionapi.ClientWithResponsesInterface, pool *unikornv1.ComputeClusterWorkloadPoolsPoolSpec) error {
	request := regionapi.SecurityGroupWrite{
		Metadata: coreapi.ResourceWriteMetadata{
			Name:        p.securityGroupName(pool),
			Description: ptr.To("Security group for cluster " + p.cluster.Name),
			Tags:        p.tags(pool),
		},
	}

	resp, err := client.PostApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDSecuritygroupsWithResponse(ctx, p.cluster.Labels[coreconstants.OrganizationLabel], p.cluster.Labels[coreconstants.ProjectLabel], p.cluster.Annotations[coreconstants.IdentityAnnotation], request)
	if err != nil {
		return err
	}

	if resp.StatusCode() != http.StatusCreated {
		return fmt.Errorf("%w: securitygroup POST expected 201 got %d", coreerrors.ErrAPIStatus, resp.StatusCode())
	}

	return nil
}

func (p *Provisioner) deleteSecurityGroup(ctx context.Context, client regionapi.ClientWithResponsesInterface, id string) error {
	resp, err := client.DeleteApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDSecuritygroupsSecurityGroupIDWithResponse(ctx, p.cluster.Labels[coreconstants.OrganizationLabel], p.cluster.Labels[coreconstants.ProjectLabel], p.cluster.Annotations[coreconstants.IdentityAnnotation], id)
	if err != nil {
		return err
	}

	if resp.StatusCode() != http.StatusAccepted && resp.StatusCode() != http.StatusNotFound {
		return fmt.Errorf("%w: securitygroup DELETE expected 202 got %d", coreerrors.ErrAPIStatus, resp.StatusCode())
	}

	return nil
}

func (p *Provisioner) createSecurityGroupRule(ctx context.Context, client regionapi.ClientWithResponsesInterface, pool *unikornv1.ComputeClusterWorkloadPoolsPoolSpec, securityGroupID string, rule *unikornv1.FirewallRule) error {
	port := &regionapi.SecurityGroupRulePort{}

	if rule.Port.Number != nil {
		port.Number = rule.Port.Number
	}

	if rule.Port.Range != nil {
		port.Range = &regionapi.SecurityGroupRulePortRange{
			Start: rule.Port.Range.Start,
			End:   rule.Port.Range.End,
		}
	}

	request := regionapi.SecurityGroupRuleWrite{
		Metadata: coreapi.ResourceWriteMetadata{
			Name:        rule.ID,
			Description: ptr.To("Security group rule for cluster " + p.cluster.Name),
			Tags:        p.tags(pool),
		},
		Spec: regionapi.SecurityGroupRuleWriteSpec{
			Direction: regionapi.SecurityGroupRuleWriteSpecDirectionIngress,
			Cidr:      rule.CIDR.String(),
			Protocol:  regionapi.SecurityGroupRuleWriteSpecProtocol(rule.Protocol),
			Port:      *port,
		},
	}

	resp, err := client.PostApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDSecuritygroupsSecurityGroupIDRulesWithResponse(ctx, p.cluster.Labels[coreconstants.OrganizationLabel], p.cluster.Labels[coreconstants.ProjectLabel], p.cluster.Annotations[coreconstants.IdentityAnnotation], securityGroupID, request)
	if err != nil {
		return err
	}

	if resp.StatusCode() != http.StatusCreated {
		return fmt.Errorf("%w: securitygrouprule POST expected 201 got %d", coreerrors.ErrAPIStatus, resp.StatusCode())
	}

	return nil
}

func (p *Provisioner) deleteSecurityGroupRule(ctx context.Context, client regionapi.ClientWithResponsesInterface, securityGroupID, ruleID string) error {
	resp, err := client.DeleteApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDSecuritygroupsSecurityGroupIDRulesRuleIDWithResponse(ctx, p.cluster.Labels[coreconstants.OrganizationLabel], p.cluster.Labels[coreconstants.ProjectLabel], p.cluster.Annotations[coreconstants.IdentityAnnotation], securityGroupID, ruleID)
	if err != nil {
		return err
	}

	if resp.StatusCode() != http.StatusAccepted && resp.StatusCode() != http.StatusNotFound {
		return fmt.Errorf("%w: securitygrouprule DELETE expected 202 got %d", coreerrors.ErrAPIStatus, resp.StatusCode())
	}

	return nil
}

func (p *Provisioner) securityGroupName(pool *unikornv1.ComputeClusterWorkloadPoolsPoolSpec) string {
	return fmt.Sprintf("%s-%s", p.cluster.Name, pool.Name)
}

func (p *Provisioner) compareFirewallRuleLists(provisioned regionapi.SecurityGroupRulesRead, desired []unikornv1.FirewallRule) ([]string, []string) {
	toDelete, toCreate := []string{}, []string{}
	provisionedSet := make(map[string]struct{})
	desiredSet := make(map[string]struct{})

	// populate sets
	for _, rule := range provisioned {
		provisionedSet[rule.Metadata.Name] = struct{}{}
	}

	for _, rule := range desired {
		desiredSet[rule.ID] = struct{}{}
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

func (p *Provisioner) getSecurityGroups(ctx context.Context, client regionapi.ClientWithResponsesInterface) (*regionapi.SecurityGroupsResponse, error) {
	response, err := client.GetApiV1OrganizationsOrganizationIDSecuritygroupsWithResponse(ctx, p.cluster.Labels[coreconstants.OrganizationLabel])
	if err != nil {
		return nil, err
	}

	if response.StatusCode() != http.StatusOK {
		return nil, fmt.Errorf("%w: securitygroup GET expected 200 got %d", coreerrors.ErrAPIStatus, response.StatusCode())
	}

	// Filter out security groups that aren't from this cluster.
	result := slices.DeleteFunc(*response.JSON200, func(sg regionapi.SecurityGroupRead) bool {
		if sg.Metadata.Tags == nil {
			return true
		}

		index := slices.IndexFunc(*sg.Metadata.Tags, func(tag coreapi.Tag) bool {
			return tag.Name == coreconstants.ComputeClusterLabel && tag.Value == p.cluster.Name
		})

		return index < 0
	})

	return &result, nil
}

func (p *Provisioner) getProvisionedSecurityGroupSet(ctx context.Context, client regionapi.ClientWithResponsesInterface) (computeprovisioners.WorkloadPoolProvisionedSecurityGroupSet, error) {
	securitygroups, err := p.getSecurityGroups(ctx, client)
	if err != nil {
		return nil, err
	}

	result := make(computeprovisioners.WorkloadPoolProvisionedSecurityGroupSet)

	for i := range *securitygroups {
		sg := (*securitygroups)[i]
		// find the security group tag
		index := slices.IndexFunc(*sg.Metadata.Tags, func(tag coreapi.Tag) bool {
			return tag.Name == WorkloadPoolLabel
		})

		if index < 0 {
			continue
		}

		poolName := (*sg.Metadata.Tags)[index].Value
		result[poolName] = &sg
	}

	return result, nil
}

func (p *Provisioner) getSecurityGroupRules(ctx context.Context, client regionapi.ClientWithResponsesInterface, securityGroupID string) (regionapi.SecurityGroupRulesResponse, error) {
	response, err := client.GetApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDSecuritygroupsSecurityGroupIDRulesWithResponse(ctx, p.cluster.Labels[coreconstants.OrganizationLabel], p.cluster.Labels[coreconstants.ProjectLabel], p.cluster.Annotations[coreconstants.IdentityAnnotation], securityGroupID)
	if err != nil {
		return nil, err
	}

	if response.StatusCode() != http.StatusOK {
		return nil, fmt.Errorf("%w: securitygrouprule GET expected 200 got %d", coreerrors.ErrAPIStatus, response.StatusCode())
	}

	return *response.JSON200, nil
}
