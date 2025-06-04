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
	"reflect"
	"slices"

	"github.com/spjmurray/go-util/pkg/set"

	unikornv1 "github.com/unikorn-cloud/compute/pkg/apis/unikorn/v1alpha1"
	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreapi "github.com/unikorn-cloud/core/pkg/openapi"
	regionapi "github.com/unikorn-cloud/region/pkg/openapi"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/utils/ptr"

	"sigs.k8s.io/controller-runtime/pkg/log"
)

// serverPoolSet maps the server name to its API resource.
type serverPoolSet map[string]*regionapi.ServerRead

// add adds a server to the set and raises an error if one already exists.
func (s serverPoolSet) add(serverName string, server *regionapi.ServerRead) error {
	if _, ok := s[serverName]; ok {
		return fmt.Errorf("%w: server %s for already exists", ErrConsistency, serverName)
	}

	s[serverName] = server

	return nil
}

// newServerSet returns a new set of servers indexed by pool and by name.
func (p *Provisioner) newServerSet(ctx context.Context, client regionapi.ClientWithResponsesInterface) (serverPoolSet, error) {
	log := log.FromContext(ctx)

	servers, err := p.listServers(ctx, client)
	if err != nil {
		return nil, err
	}

	result := serverPoolSet{}

	for i := range servers {
		server := &servers[i]

		if err := result.add(server.Metadata.Name, server); err != nil {
			return nil, err
		}
	}

	log.Info("reading existing servers for cluster", "servers", result)

	return result, nil
}

func serverName(pool *unikornv1.ComputeClusterWorkloadPoolSpec, replicaIndex int) string {
	// naive implementation to create a server name based on the pool name and replica index
	return fmt.Sprintf("%s-%d", pool.Name, replicaIndex)
}

// getSecurityGroupForPool returns the security group for a pool.  It assumes the main provisioner
// has waited until all security groups are ready before proceeding.
func generateSecurityGroup(pool *unikornv1.ComputeClusterWorkloadPoolSpec, securityGroups securityGroupSet) (*regionapi.ServerSecurityGroupList, error) {
	if !pool.HasFirewallRules() {
		//nolint:nilnil
		return nil, nil
	}

	securityGroup, ok := securityGroups[pool.Name]
	if !ok {
		return nil, fmt.Errorf("%w: security group for server pool %s not found", ErrConsistency, pool.Name)
	}

	result := &regionapi.ServerSecurityGroupList{
		regionapi.ServerSecurityGroup{
			Id: securityGroup.Metadata.Id,
		},
	}

	return result, nil
}

// generateUserData generates user data for a server request.
func generateUserData(pool *unikornv1.ComputeClusterWorkloadPoolSpec) *[]byte {
	if pool.UserData == nil {
		return nil
	}

	return &pool.UserData
}

// generateServer generates a server request for creation and updates.
func (p *Provisioner) generateServer(name string, openstackIdentityStatus *openstackIdentityStatus, pool *unikornv1.ComputeClusterWorkloadPoolSpec, securityGroups securityGroupSet) (*regionapi.ServerWrite, error) {
	securityGroup, err := generateSecurityGroup(pool, securityGroups)
	if err != nil {
		return nil, err
	}

	request := &regionapi.ServerWrite{
		Metadata: coreapi.ResourceWriteMetadata{
			Name:        name,
			Description: ptr.To("Server for cluster " + p.cluster.Name),
			Tags:        p.tags(pool),
		},
		Spec: regionapi.ServerSpec{
			FlavorId: pool.FlavorID,
			ImageId:  pool.ImageID,
			Networks: regionapi.ServerNetworkList{
				regionapi.ServerNetwork{
					Id: openstackIdentityStatus.NetworkID,
				},
			},
			PublicIPAllocation: &regionapi.ServerPublicIPAllocation{
				Enabled: pool.PublicIPAllocation != nil && pool.PublicIPAllocation.Enabled,
			},
			SecurityGroups: securityGroup,
			UserData:       generateUserData(pool),
		},
	}

	return request, nil
}

// serverCreateSet maps server name to it create request.
type serverCreateSet map[string]*regionapi.ServerWrite

// add adds a server to the set and raises an error if one already exists.
func (s serverCreateSet) add(serverName string, server *regionapi.ServerWrite) error {
	if _, ok := s[serverName]; ok {
		return fmt.Errorf("%w: server %s for pool already", ErrConsistency, serverName)
	}

	s[serverName] = server

	return nil
}

// generateServerCreateSet creates a set of all servers that need to exist.
func (p *Provisioner) generateServerCreateSet(openstackIdentityStatus *openstackIdentityStatus, securityGroups securityGroupSet) (serverCreateSet, error) {
	out := serverCreateSet{}

	for i := range p.cluster.Spec.WorkloadPools.Pools {
		pool := &p.cluster.Spec.WorkloadPools.Pools[i]

		for index := range pool.Replicas {
			name := serverName(pool, index)

			request, err := p.generateServer(name, openstackIdentityStatus, pool, securityGroups)
			if err != nil {
				return nil, err
			}

			if err := out.add(name, request); err != nil {
				return nil, err
			}
		}
	}

	return out, nil
}

// needsUpdate compares both specifications and determines whether we need a resource update.
func needsUpdate(current *regionapi.ServerRead, requested *regionapi.ServerWrite) bool {
	return !reflect.DeepEqual(current.Spec, requested.Spec)
}

// needsRebuild compares the current and requested specifications to determine whether
// we should do an inplace update of the resource (where supported) or rebuild it from
// scratch.
func needsRebuild(current *regionapi.ServerRead, requested *regionapi.ServerWrite) bool {
	// TODO: flavors can usually be scaled up without losing data but this requires
	// a shutdown, resize, possible confirmation due to a cold migration, and then
	// a restart.
	if current.Spec.FlavorId != requested.Spec.FlavorId {
		return true
	}

	if current.Spec.ImageId != requested.Spec.ImageId {
		return true
	}

	// TODO: how to handle user data is as yet unknown.  Theoretically we can just
	// update it and it'll take effect on a reboot without having to lose data,
	// which is probably preferable.  Who is in charge of the reboot?  Or the user
	// may want to blow the machine away and reprovision from scratch.  This probably
	// needs user interaction eventually.
	if current.Spec.UserData != requested.Spec.UserData {
		return true
	}

	return false
}

// scheduleServers compares the provisioned servers with the desired servers and returns the name of the servers to create, reconcile and delete.
func scheduleServers(current serverPoolSet, requested serverCreateSet) (set.Set[string], set.Set[string], set.Set[string]) {
	currentNames := set.New[string](slices.Collect(maps.Keys(current))...)
	requestedNames := set.New[string](slices.Collect(maps.Keys(requested))...)

	return requestedNames.Difference(currentNames), currentNames.Intersection(requestedNames), currentNames.Difference(requestedNames)
}

// deleteServerWrapper wraps up common server deletion handling as it's called from
// multiple different places.
func (p *Provisioner) deleteServerWrapper(ctx context.Context, client regionapi.ClientWithResponsesInterface, servers serverPoolSet, name string) error {
	log := log.FromContext(ctx)

	server := servers[name]

	log.Info("deleting server", "id", server.Metadata.Id, "name", name)

	if err := p.deleteServer(ctx, client, server.Metadata.Id); err != nil {
		return err
	}

	server.Metadata.ProvisioningStatus = coreapi.ResourceProvisioningStatusDeprovisioning

	return nil
}

// reconcileServers creates/updates/deletes all servers for the cluster.
//
//nolint:cyclop
func (p *Provisioner) reconcileServers(ctx context.Context, client regionapi.ClientWithResponsesInterface, servers serverPoolSet, securitygroups securityGroupSet, openstackIdentityStatus *openstackIdentityStatus) error {
	log := log.FromContext(ctx)

	required, err := p.generateServerCreateSet(openstackIdentityStatus, securitygroups)
	if err != nil {
		return err
	}

	create, update, remove := scheduleServers(servers, required)

	// If any servers exist that shouldn't delete them.
	for name := range remove.All() {
		if err := p.deleteServerWrapper(ctx, client, servers, name); err != nil {
			return err
		}
	}

	// If any servers have been modified, we need to see if it's something that can
	// actually be done online or not.  For now we allow changing network options,
	// everything else needs a rebuild.
	for name := range update.All() {
		server := servers[name]
		request := required[name]

		if !needsUpdate(server, request) {
			continue
		}

		if needsRebuild(server, request) {
			if err := p.deleteServerWrapper(ctx, client, servers, name); err != nil {
				return err
			}

			// Ensure we recreate next time around.
			p.needsRetry = true

			continue
		}

		log.Info("updating server", "name", name)

		updated, err := p.updateServer(ctx, client, server.Metadata.Id, request)
		if err != nil {
			return err
		}

		servers[name] = updated

		// There is a delay between the API performing the request and the provisioning
		// status kicking in, so we may miss resource updates.
		p.needsRetry = true
	}

	// Create any that we can this time around.
	for name := range create.All() {
		log.Info("creating server", "name", name)

		request := required[name]

		server, err := p.createServer(ctx, client, request)
		if err != nil {
			return err
		}

		if err := servers.add(name, server); err != nil {
			return err
		}
	}

	return nil
}

// convertProvisioningStatusCondition converts from an OpenAPI status condition into a Kubernetes one.
func convertProvisioningStatusCondition(in coreapi.ResourceProvisioningStatus) (corev1.ConditionStatus, unikornv1core.ConditionReason) {
	//nolint:exhaustive
	switch in {
	case coreapi.ResourceProvisioningStatusProvisioning:
		return corev1.ConditionFalse, unikornv1core.ConditionReasonProvisioning
	case coreapi.ResourceProvisioningStatusDeprovisioning:
		return corev1.ConditionFalse, unikornv1core.ConditionReasonDeprovisioning
	case coreapi.ResourceProvisioningStatusProvisioned:
		return corev1.ConditionTrue, unikornv1core.ConditionReasonProvisioned
	case coreapi.ResourceProvisioningStatusError:
		return corev1.ConditionFalse, unikornv1core.ConditionReasonErrored
	}

	return corev1.ConditionFalse, unikornv1core.ConditionReasonUnknown
}

// convertHealthStatusCondition converts from an OpenAPI status condition into a Kubernetes one.
func convertHealthStatusCondition(in coreapi.ResourceHealthStatus) (corev1.ConditionStatus, unikornv1core.ConditionReason) {
	//nolint:exhaustive
	switch in {
	case coreapi.ResourceHealthStatusHealthy:
		return corev1.ConditionTrue, unikornv1core.ConditionReasonHealthy
	case coreapi.ResourceHealthStatusDegraded:
		return corev1.ConditionFalse, unikornv1core.ConditionReasonDegraded
	}

	return corev1.ConditionFalse, unikornv1core.ConditionReasonUnknown
}

// updateServerStatus adds a server to the cluster's status.
// This is called unconditionally after a reconcile to update the current
// machine status.  It also sets a global flag if any servers are not
// available so that we can yield and perform any remedial action until
// everything becomes healthy.
func (p *Provisioner) updateServerStatus(server *regionapi.ServerRead) error {
	poolName, err := getWorkloadPoolTag(server.Metadata.Tags)
	if err != nil {
		return err
	}

	poolStatus := p.cluster.GetWorkloadPoolStatus(poolName)
	poolStatus.Replicas++

	status := unikornv1.MachineStatus{
		Hostname:  server.Metadata.Name,
		FlavorID:  server.Spec.FlavorId,
		ImageID:   server.Spec.ImageId,
		PrivateIP: server.Status.PrivateIP,
		PublicIP:  server.Status.PublicIP,
	}

	provisioningStatus, provisioningReason := convertProvisioningStatusCondition(server.Metadata.ProvisioningStatus)
	healthStatus, healthReason := convertHealthStatusCondition(server.Metadata.HealthStatus)

	unikornv1core.UpdateCondition(&status.Conditions, unikornv1core.ConditionAvailable, provisioningStatus, provisioningReason, "server provisioning")
	unikornv1core.UpdateCondition(&status.Conditions, unikornv1core.ConditionHealthy, healthStatus, healthReason, "server provisioning")

	poolStatus.Machines = append(poolStatus.Machines, status)

	if provisioningStatus == corev1.ConditionFalse {
		p.needsRetry = true
	}

	return nil
}
