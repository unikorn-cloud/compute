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

// Security groups are optional per workload pool, and there is at most one per pool.
// Security groups identify their owning pool by using resource tags.  This means
// security groups will only ever need to be created or deleted.
// Security group rules are identified by building a unique tuple from all their
// elements (direction, port range and allowed prefixes) and therefore will also
// only ever need to be created or deleted.

import (
	"context"
	"fmt"
	"maps"
	"slices"

	"github.com/spjmurray/go-util/pkg/set"

	unikornv1 "github.com/unikorn-cloud/compute/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/compute/pkg/provisioners/managers/cluster/util"
	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreapi "github.com/unikorn-cloud/core/pkg/openapi"
	regionapi "github.com/unikorn-cloud/region/pkg/openapi"

	"k8s.io/utils/ptr"

	"sigs.k8s.io/controller-runtime/pkg/log"
)

// securityGroupSet contains a set of security groups, indexed by pool name.
type securityGroupSet map[string]*regionapi.SecurityGroupRead

// add adds a security group to the set and raises an error if one already exists.
func (s securityGroupSet) add(poolName string, securityGroup *regionapi.SecurityGroupRead) error {
	if _, ok := s[poolName]; ok {
		return fmt.Errorf("%w: security group for pool %s already exists", ErrConsistency, poolName)
	}

	s[poolName] = securityGroup

	return nil
}

// newSecurityGroupSet returns a set of security groups, indexed by pool name.
func (p *Provisioner) newSecurityGroupSet(ctx context.Context, client regionapi.ClientWithResponsesInterface) (securityGroupSet, error) {
	log := log.FromContext(ctx)

	securityGroups, err := p.listSecurityGroups(ctx, client)
	if err != nil {
		return nil, err
	}

	result := securityGroupSet{}

	for i := range securityGroups {
		securityGroup := &securityGroups[i]

		poolName, err := util.GetWorkloadPoolTag(securityGroup.Metadata.Tags)
		if err != nil {
			return nil, err
		}

		if err := result.add(poolName, securityGroup); err != nil {
			return nil, err
		}
	}

	log.Info("reading existing security groups for cluster", "securityGroups", result)

	return result, nil
}

// securityGroupName generates a unique security group name from the cluster and pool.
func (p *Provisioner) securityGroupName(pool *unikornv1.ComputeClusterWorkloadPoolSpec) string {
	return fmt.Sprintf("%s-%s", p.cluster.Name, pool.Name)
}

// generateSecurityGroup creates a new security group request.
func (p *Provisioner) generateSecurityGroup(pool *unikornv1.ComputeClusterWorkloadPoolSpec) *regionapi.SecurityGroupWrite {
	return &regionapi.SecurityGroupWrite{
		Metadata: coreapi.ResourceWriteMetadata{
			Name:        p.securityGroupName(pool),
			Description: ptr.To("Security group for cluster " + p.cluster.Name),
			Tags:        p.tags(pool),
		},
	}
}

// securityGroupCreateSet defines all security groups that should exist.
type securityGroupCreateSet map[string]*regionapi.SecurityGroupWrite

// add adds a security group to the set and raises an error if one already exists.
func (s securityGroupCreateSet) add(poolName string, securityGroup *regionapi.SecurityGroupWrite) error {
	if _, ok := s[poolName]; ok {
		return fmt.Errorf("%w: security group for pool %s already", ErrConsistency, poolName)
	}

	s[poolName] = securityGroup

	return nil
}

// generateSecurityGroupCreateSet creates a set of all security groups that need to exist.
func (p *Provisioner) generateSecurityGroupCreateSet() (securityGroupCreateSet, error) {
	out := securityGroupCreateSet{}

	for i := range p.cluster.Spec.WorkloadPools.Pools {
		pool := &p.cluster.Spec.WorkloadPools.Pools[i]

		if !pool.HasFirewallRules() {
			continue
		}

		if err := out.add(pool.Name, p.generateSecurityGroup(pool)); err != nil {
			return nil, err
		}
	}

	return out, nil
}

// scheduleServerGroups determines what needs to be created/updated/deleted.
func scheduleServerGroups(current securityGroupSet, requested securityGroupCreateSet) (set.Set[string], set.Set[string], set.Set[string]) {
	currentNames := set.New[string](slices.Collect(maps.Keys(current))...)
	requestedNames := set.New[string](slices.Collect(maps.Keys(requested))...)

	return requestedNames.Difference(currentNames), currentNames.Intersection(requestedNames), currentNames.Difference(requestedNames)
}

// reconcileSecurityGroups iterates through all pools and ensures any server groups that
// are required exist.
func (p *Provisioner) reconcileSecurityGroups(ctx context.Context, client regionapi.ClientWithResponsesInterface, securityGroups securityGroupSet) error {
	log := log.FromContext(ctx)

	required, err := p.generateSecurityGroupCreateSet()
	if err != nil {
		return err
	}

	create, update, remove := scheduleServerGroups(securityGroups, required)

	for poolName := range create.All() {
		request := required[poolName]

		log.Info("creating security group", "pool", poolName, "name", request.Metadata.Name)

		securityGroup, err := p.createSecurityGroup(ctx, client, request)
		if err != nil {
			return err
		}

		if err := securityGroups.add(poolName, securityGroup); err != nil {
			return err
		}

		if err := p.reconcileSecurityGroupRules(ctx, client, poolName, securityGroup); err != nil {
			return err
		}
	}

	for poolName := range update.All() {
		securityGroup := securityGroups[poolName]

		if err := p.reconcileSecurityGroupRules(ctx, client, poolName, securityGroup); err != nil {
			return err
		}
	}

	for poolName := range remove.All() {
		securityGroup := securityGroups[poolName]

		log.Info("deleting security group", "pool", poolName, "id", securityGroup.Metadata.Id, "name", securityGroup.Metadata.Name)

		if err := p.deleteSecurityGroup(ctx, client, securityGroup.Metadata.Id); err != nil {
			return err
		}
	}

	return nil
}

// securityGroupID generates a unqiue rule ID.  It either exists or it doesn't
// there is no aliasing or need to update via the API.
func securityGroupIDGenerate(in *regionapi.SecurityGroupRuleSpec) string {
	id := fmt.Sprintf("%s-%s", in.Direction, in.Protocol)

	if in.Port.Number != nil {
		id += fmt.Sprintf("-%d", *in.Port.Number)
	} else {
		id += fmt.Sprintf("-%d-%d", in.Port.Range.Start, in.Port.Range.End)
	}

	id += fmt.Sprintf("-%s", in.Cidr)

	return id
}

// generateRequiredSecurityGroupRule generates a single security group rule request.
func (p *Provisioner) generateRequiredSecurityGroupRule(pool *unikornv1.ComputeClusterWorkloadPoolSpec, in *unikornv1.FirewallRule, prefix unikornv1core.IPv4Prefix) *regionapi.SecurityGroupRuleWrite {
	rule := &regionapi.SecurityGroupRuleWrite{
		Metadata: coreapi.ResourceWriteMetadata{
			Name: "unikorn-compute-cluster-security-group",
			Tags: p.tags(pool),
		},
		Spec: regionapi.SecurityGroupRuleSpec{
			Direction: regionapi.NetworkDirection(in.Direction),
			Protocol:  regionapi.NetworkProtocol(in.Protocol),
			Cidr:      prefix.String(),
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
func (p *Provisioner) generateRequiredSecurityGroupRules(pool *unikornv1.ComputeClusterWorkloadPoolSpec) map[string]*regionapi.SecurityGroupRuleWrite {
	out := map[string]*regionapi.SecurityGroupRuleWrite{}

	for i := range pool.Firewall {
		for _, prefix := range pool.Firewall[i].Prefixes {
			rule := p.generateRequiredSecurityGroupRule(pool, &pool.Firewall[i], prefix)

			out[securityGroupIDGenerate(&rule.Spec)] = rule
		}
	}

	return out
}

// securityGroupRuleIDMap is a set of security group rules for the cluster
// indexed by security group ID (which is a unique tuple of direction, port range
// and allowed address ranges).
type securityGroupRuleIDMap map[string]*regionapi.SecurityGroupRuleRead

// getSecurityGroupRuleIDMap gets a set of security group rules for the cluster
// indexed by security group ID.
func (p *Provisioner) getSecurityGroupRuleIDMap(ctx context.Context, client regionapi.ClientWithResponsesInterface, securityGroupID string) (securityGroupRuleIDMap, error) {
	rules, err := p.listSecurityGroupRules(ctx, client, securityGroupID)
	if err != nil {
		return nil, err
	}

	out := securityGroupRuleIDMap{}

	for i := range rules {
		out[securityGroupIDGenerate(&rules[i].Spec)] = &rules[i]
	}

	return out, nil
}

// scheduleSecurityGroupRules does some simple boolean logic on the requested and existing
// rule IDs to determine what needs to be created, and what needs to be deleted.
func (p *Provisioner) scheduleSecurityGroupRules(provisioned map[string]*regionapi.SecurityGroupRuleRead, desired map[string]*regionapi.SecurityGroupRuleWrite) (set.Set[string], set.Set[string]) {
	actualIDs := set.New[string](slices.Collect(maps.Keys(provisioned))...)
	desiredIDs := set.New[string](slices.Collect(maps.Keys(desired))...)

	return desiredIDs.Difference(actualIDs), actualIDs.Difference(desiredIDs)
}

// reconcileSecurityGroupRules creates and deletes rules for a security group
// as needed.  It is assumed the region controller is responsible for synchronization
// with the userlying cloud provider.
func (p *Provisioner) reconcileSecurityGroupRules(ctx context.Context, client regionapi.ClientWithResponsesInterface, poolName string, securitygroup *regionapi.SecurityGroupRead) error {
	log := log.FromContext(ctx)

	pool, ok := p.cluster.GetWorkloadPool(poolName)
	if !ok {
		return fmt.Errorf("%w: pool lookup failed", ErrConsistency)
	}

	provisionedRules, err := p.getSecurityGroupRuleIDMap(ctx, client, securitygroup.Metadata.Id)
	if err != nil {
		return err
	}

	required := p.generateRequiredSecurityGroupRules(pool)

	create, remove := p.scheduleSecurityGroupRules(provisionedRules, required)

	for id := range remove.All() {
		log.Info("deleting security group rule", "securityGroup", securitygroup.Metadata.Id, "rule", id)

		if err := p.deleteSecurityGroupRule(ctx, client, securitygroup.Metadata.Id, provisionedRules[id].Metadata.Id); err != nil {
			return err
		}
	}

	for id := range create.All() {
		log.Info("creating security group rule", "securityGroup", securitygroup.Metadata.Id, "rule", id)

		if _, err := p.createSecurityGroupRule(ctx, client, securitygroup.Metadata.Id, required[id]); err != nil {
			return err
		}
	}

	return nil
}
