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
	"github.com/unikorn-cloud/core/pkg/provisioners"
	regionapi "github.com/unikorn-cloud/region/pkg/openapi"
	"k8s.io/utils/ptr"
)

func (p *Provisioner) createSecurityGroup(ctx context.Context, client regionapi.ClientWithResponsesInterface, pool *unikornv1.ComputeClusterWorkloadPoolsPoolSpec) (*regionapi.SecurityGroupRead, error) {
	request := regionapi.SecurityGroupWrite{
		Metadata: coreapi.ResourceWriteMetadata{
			Name:        p.securityGroupName(pool),
			Description: ptr.To("Security group for cluster " + p.cluster.Name),
		},
		Spec: &regionapi.SecurityGroupWriteSpec{
			Tags: p.tags(pool),
		},
	}

	resp, err := client.PostApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDSecuritygroupsWithResponse(ctx, p.cluster.Labels[coreconstants.OrganizationLabel], p.cluster.Labels[coreconstants.ProjectLabel], p.cluster.Annotations[coreconstants.IdentityAnnotation], request)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode() != http.StatusCreated {
		return nil, fmt.Errorf("%w: securitygroup POST expected 201 got %d", coreerrors.ErrAPIStatus, resp.StatusCode())
	}

	return resp.JSON201, nil
}

func (p *Provisioner) deleteSecurityGroup(ctx context.Context, client regionapi.ClientWithResponsesInterface, ID string) error {
	resp, err := client.DeleteApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDSecuritygroupsSecurityGroupIDWithResponse(ctx, p.cluster.Labels[coreconstants.OrganizationLabel], p.cluster.Labels[coreconstants.ProjectLabel], p.cluster.Annotations[coreconstants.IdentityAnnotation], ID)
	if err != nil {
		return err
	}

	if resp.StatusCode() != http.StatusAccepted && resp.StatusCode() != http.StatusNotFound {
		return fmt.Errorf("%w: securitygroup DELETE expected 202 got %d", coreerrors.ErrAPIStatus, resp.StatusCode())
	}

	return nil
}

func (p *Provisioner) securityGroupRuleName(pool *unikornv1.ComputeClusterWorkloadPoolsPoolSpec) string {
	return fmt.Sprintf("%s-%s", p.cluster.Name, pool.Name)
}

func (p *Provisioner) createSecurityGroupRule(ctx context.Context, client regionapi.ClientWithResponsesInterface, pool *unikornv1.ComputeClusterWorkloadPoolsPoolSpec, securityGroupID *string, rule *unikornv1.FirewallRule) (*regionapi.SecurityGroupRuleRead, error) {
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
			Name:        p.securityGroupRuleName(pool),
			Description: ptr.To("Security group rule for cluster " + p.cluster.Name),
		},
		Spec: regionapi.SecurityGroupRuleWriteSpec{
			Direction: regionapi.SecurityGroupRuleWriteSpecDirectionIngress,
			Cidr:      rule.CIDR.String(),
			Protocol:  regionapi.SecurityGroupRuleWriteSpecProtocol(rule.Protocol),
			Port:      *port,
		},
	}

	resp, err := client.PostApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDSecuritygroupsSecurityGroupIDRulesWithResponse(ctx, p.cluster.Labels[coreconstants.OrganizationLabel], p.cluster.Labels[coreconstants.ProjectLabel], p.cluster.Annotations[coreconstants.IdentityAnnotation], *securityGroupID, request)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode() != http.StatusCreated {
		return nil, fmt.Errorf("%w: securitygrouprule POST expected 201 got %d", coreerrors.ErrAPIStatus, resp.StatusCode())
	}

	return resp.JSON201, nil
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

func (p *Provisioner) lookupPoolSecurityGroup(securityGroups *regionapi.SecurityGroupsRead, pool *unikornv1.ComputeClusterWorkloadPoolsPoolSpec) *regionapi.SecurityGroupRead {
	sg := *securityGroups

	index := slices.IndexFunc(sg, func(sg regionapi.SecurityGroupRead) bool {
		return sg.Metadata.Name == p.securityGroupName(pool)
	})

	if index >= 0 {
		return &sg[index]
	}

	return nil
}

func (p *Provisioner) reconcileSecurityGroup(ctx context.Context, client regionapi.ClientWithResponsesInterface, pool *unikornv1.ComputeClusterWorkloadPoolsPoolSpec) error {
	firewallStatus := p.lookupWorkloadPoolFirewallStatus(pool)

	if firewallStatus.ProviderID == nil && pool.Firewall == nil {
		// nothing to do
		return nil
	}

	if firewallStatus.ProviderID != nil && pool.Firewall == nil {
		if err := p.deleteSecurityGroup(ctx, client, *firewallStatus.ProviderID); err != nil {
			return err
		}

		firewallStatus.ProviderID = nil
		firewallStatus.Ingress = nil
	}

	if firewallStatus.ProviderID == nil && pool.Firewall != nil {
		resp, err := p.createSecurityGroup(ctx, client, pool)
		if err != nil {
			return err
		}

		// update status
		firewallStatus.ProviderID = &resp.Metadata.Id
	}

	if err := p.reconcileSecurityGroupRules(ctx, client, pool); err != nil {
		return err
	}

	return nil
}

func (p *Provisioner) reconcileSecurityGroupRules(ctx context.Context, client regionapi.ClientWithResponsesInterface, pool *unikornv1.ComputeClusterWorkloadPoolsPoolSpec) error {
	firewallStatus := p.lookupWorkloadPoolFirewallStatus(pool)
	if firewallStatus.ProviderID == nil {
		// wait until security group is created
		return provisioners.ErrYield
	}

	toDelete, toCreate := p.compareFirewallRuleLists(firewallStatus.Ingress, pool.Firewall.Ingress)

	for _, id := range toDelete {
		index := slices.IndexFunc(firewallStatus.Ingress, func(rs unikornv1.FirewallRuleStatus) bool {
			return rs.ID == id
		})

		if err := p.deleteSecurityGroupRule(ctx, client, *firewallStatus.ProviderID, *firewallStatus.Ingress[index].ProviderID); err != nil {
			return err
		}

		p.patchWorkloadPoolFirewallIngressStatus(firewallStatus, id, nil)
	}

	for _, id := range toCreate {
		index := slices.IndexFunc(pool.Firewall.Ingress, func(rule unikornv1.FirewallRule) bool {
			return rule.ID == id
		})

		resp, err := p.createSecurityGroupRule(ctx, client, pool, firewallStatus.ProviderID, &pool.Firewall.Ingress[index])
		if err != nil {
			return err
		}

		p.patchWorkloadPoolFirewallIngressStatus(firewallStatus, pool.Firewall.Ingress[index].ID, &resp.Metadata.Id)
	}

	return nil
}

func (p *Provisioner) patchWorkloadPoolFirewallIngressStatus(firewallStatus *unikornv1.FirewallStatus, ruleID string, providerID *string) {
	index := slices.IndexFunc(firewallStatus.Ingress, func(rule unikornv1.FirewallRuleStatus) bool {
		return rule.ID == ruleID
	})

	if index >= 0 {
		firewallStatus.Ingress[index].ProviderID = providerID
		return
	}

	firewallStatus.Ingress = append(firewallStatus.Ingress, unikornv1.FirewallRuleStatus{
		ID:         ruleID,
		ProviderID: providerID,
	})
}

func (p *Provisioner) lookupWorkloadPoolStatus(pool *unikornv1.ComputeClusterWorkloadPoolsPoolSpec) *unikornv1.ComputeClusterWorkloadPoolStatus {
	index := slices.IndexFunc(p.cluster.Status.WorkloadPools, func(wp unikornv1.ComputeClusterWorkloadPoolStatus) bool {
		return wp.Name == pool.Name
	})

	if index < 0 {
		p.cluster.Status.WorkloadPools = append(p.cluster.Status.WorkloadPools, unikornv1.ComputeClusterWorkloadPoolStatus{
			Name:     pool.Name,
			Firewall: &unikornv1.FirewallStatus{},
		})

		return &p.cluster.Status.WorkloadPools[len(p.cluster.Status.WorkloadPools)-1]
	}

	return &p.cluster.Status.WorkloadPools[index]
}

func (p *Provisioner) lookupWorkloadPoolFirewallStatus(pool *unikornv1.ComputeClusterWorkloadPoolsPoolSpec) *unikornv1.FirewallStatus {
	poolStatus := p.lookupWorkloadPoolStatus(pool)

	return poolStatus.Firewall
}

func (p *Provisioner) compareFirewallRuleLists(provisioned []unikornv1.FirewallRuleStatus, desired []unikornv1.FirewallRule) (toDelete, toCreate []string) {
	provisionedSet := make(map[string]struct{})
	desiredSet := make(map[string]struct{})

	// populate sets
	for _, rule := range provisioned {
		if rule.ProviderID != nil {
			provisionedSet[rule.ID] = struct{}{}
		}
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
