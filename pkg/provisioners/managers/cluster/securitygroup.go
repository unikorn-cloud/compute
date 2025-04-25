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
	"github.com/unikorn-cloud/core/pkg/provisioners"
	coreapiutils "github.com/unikorn-cloud/core/pkg/util/api"
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

// TODO: share types.
func securityGroupIDWrite(in *regionapi.SecurityGroupRuleWrite) string {
	id := fmt.Sprintf("%s-%s", in.Spec.Direction, in.Spec.Protocol)

	if in.Spec.Port.Number != nil {
		id += fmt.Sprintf("-%d", *in.Spec.Port.Number)
	} else {
		id += fmt.Sprintf("-%d-%d", in.Spec.Port.Range.Start, in.Spec.Port.Range.End)
	}

	id += fmt.Sprintf("-%s", in.Spec.Cidr)

	return id
}

// TODO: share types.
func securityGroupIDRead(in *regionapi.SecurityGroupRuleRead) string {
	id := fmt.Sprintf("%s-%s", in.Spec.Direction, in.Spec.Protocol)

	if in.Spec.Port.Number != nil {
		id += fmt.Sprintf("-%d", *in.Spec.Port.Number)
	} else {
		id += fmt.Sprintf("-%d-%d", in.Spec.Port.Range.Start, in.Spec.Port.Range.End)
	}

	id += fmt.Sprintf("-%s", in.Spec.Cidr)

	return id
}

func (p *Provisioner) generateRequiredSecurityGroupRule(pool *unikornv1.ComputeClusterWorkloadPoolsPoolSpec, in *unikornv1.FirewallRule, prefix unikornv1core.IPv4Prefix) *regionapi.SecurityGroupRuleWrite {
	rule := &regionapi.SecurityGroupRuleWrite{
		Metadata: coreapi.ResourceWriteMetadata{
			Name: "unikorn-compute-cluster-security-group",
			Tags: p.tags(pool),
		},
		Spec: regionapi.SecurityGroupRuleWriteSpec{
			Direction: regionapi.SecurityGroupRuleWriteSpecDirection(in.Direction),
			Protocol:  regionapi.SecurityGroupRuleWriteSpecProtocol(in.Protocol),
			Cidr:      prefix.IPNet.String(),
		},
	}

	// TODO: Smell code.  I think the region controller should be responsible
	// for managing CIDR handling.
	if in.PortMax != nil {
		rule.Spec.Port.Range = &regionapi.SecurityGroupRulePortRange{
			Start: in.Port,
			End:   *in.PortMax,
		}
	} else {
		rule.Spec.Port.Number = &in.Port
	}

	return rule
}

// generateRequiredSecurityGroupRules creates all the security group rules we require based on
// the input specification.  It essentially translates from our simple user facing API to that
// employed by the region controller.
func (p *Provisioner) generateRequiredSecurityGroupRules(pool *unikornv1.ComputeClusterWorkloadPoolsPoolSpec) map[string]*regionapi.SecurityGroupRuleWrite {
	out := map[string]*regionapi.SecurityGroupRuleWrite{}

	for i := range pool.Firewall {
		for _, prefix := range pool.Firewall[i].Prefixes {
			rule := p.generateRequiredSecurityGroupRule(pool, &pool.Firewall[i], prefix)

			out[securityGroupIDWrite(rule)] = rule
		}
	}

	return out
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

	requiredRules := p.generateRequiredSecurityGroupRules(pool)

	create, remove := p.compareFirewallRuleLists(provisionedRules, requiredRules)

	for id := range remove.All() {
		if err := p.deleteSecurityGroupRule(ctx, client, securitygroup.Metadata.Id, provisionedRules[id].Metadata.Id); err != nil {
			return err
		}
	}

	for id := range create.All() {
		if err := p.createSecurityGroupRule(ctx, client, securitygroup.Metadata.Id, requiredRules[id]); err != nil {
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
		return coreapiutils.ExtractError(resp.StatusCode(), resp)
	}

	return nil
}

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

func (p *Provisioner) createSecurityGroupRule(ctx context.Context, client regionapi.ClientWithResponsesInterface, securityGroupID string, request *regionapi.SecurityGroupRuleWrite) error {
	resp, err := client.PostApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDSecuritygroupsSecurityGroupIDRulesWithResponse(ctx, p.cluster.Labels[coreconstants.OrganizationLabel], p.cluster.Labels[coreconstants.ProjectLabel], p.cluster.Annotations[coreconstants.IdentityAnnotation], securityGroupID, *request)
	if err != nil {
		return err
	}

	if resp.StatusCode() != http.StatusCreated {
		return coreapiutils.ExtractError(resp.StatusCode(), resp)
	}

	return nil
}

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

func (p *Provisioner) securityGroupName(pool *unikornv1.ComputeClusterWorkloadPoolsPoolSpec) string {
	return fmt.Sprintf("%s-%s", p.cluster.Name, pool.Name)
}

func (p *Provisioner) compareFirewallRuleLists(provisioned map[string]*regionapi.SecurityGroupRuleRead, desired map[string]*regionapi.SecurityGroupRuleWrite) (set.Set[string], set.Set[string]) {
	actualIDs := set.New[string](slices.Collect(maps.Keys(provisioned))...)

	desiredIDs := set.New[string](slices.Collect(maps.Keys(desired))...)

	return desiredIDs.Difference(actualIDs), actualIDs.Difference(desiredIDs)
}

func (p *Provisioner) getSecurityGroups(ctx context.Context, client regionapi.ClientWithResponsesInterface) (*regionapi.SecurityGroupsResponse, error) {
	response, err := client.GetApiV1OrganizationsOrganizationIDSecuritygroupsWithResponse(ctx, p.cluster.Labels[coreconstants.OrganizationLabel])
	if err != nil {
		return nil, err
	}

	if response.StatusCode() != http.StatusOK {
		return nil, coreapiutils.ExtractError(response.StatusCode(), response)
	}

	// Filter out security groups that aren't from this cluster.
	result := slices.DeleteFunc(*response.JSON200, func(sg regionapi.SecurityGroupRead) bool {
		return p.filterComputeCluster(sg.Metadata.Tags)
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

func (p *Provisioner) getSecurityGroupRules(ctx context.Context, client regionapi.ClientWithResponsesInterface, securityGroupID string) (map[string]*regionapi.SecurityGroupRuleRead, error) {
	response, err := client.GetApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDSecuritygroupsSecurityGroupIDRulesWithResponse(ctx, p.cluster.Labels[coreconstants.OrganizationLabel], p.cluster.Labels[coreconstants.ProjectLabel], p.cluster.Annotations[coreconstants.IdentityAnnotation], securityGroupID)
	if err != nil {
		return nil, err
	}

	if response.StatusCode() != http.StatusOK {
		return nil, coreapiutils.ExtractError(response.StatusCode(), response)
	}

	out := map[string]*regionapi.SecurityGroupRuleRead{}

	rules := *response.JSON200

	for i := range rules {
		out[securityGroupIDRead(&rules[i])] = &rules[i]
	}

	return out, nil
}
