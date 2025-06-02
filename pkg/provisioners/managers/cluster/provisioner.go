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
	"errors"
	"slices"
	"strings"

	"github.com/spf13/pflag"

	unikornv1 "github.com/unikorn-cloud/compute/pkg/apis/unikorn/v1alpha1"
	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreclient "github.com/unikorn-cloud/core/pkg/client"
	"github.com/unikorn-cloud/core/pkg/manager"
	"github.com/unikorn-cloud/core/pkg/provisioners"
	identityclient "github.com/unikorn-cloud/identity/pkg/client"
	regionclient "github.com/unikorn-cloud/region/pkg/client"
	regionapi "github.com/unikorn-cloud/region/pkg/openapi"

	"sigs.k8s.io/controller-runtime/pkg/log"
)

var (
	ErrAnnotation = errors.New("required annotation missing")

	ErrResourceDependency = errors.New("resource deplendedncy error")
)

// Options allows access to CLI options in the provisioner.
type Options struct {
	// identityOptions allow the identity host and CA to be set.
	identityOptions *identityclient.Options
	// regionOptions allows the region host and CA to be set.
	regionOptions *regionclient.Options
	// clientOptions give access to client certificate information as
	// we need to talk to identity to get a token, and then to region
	// to ensure cloud identities and networks are provisioned, as well
	// as deptovisioning them.
	clientOptions coreclient.HTTPClientOptions
}

func (o *Options) AddFlags(f *pflag.FlagSet) {
	if o.identityOptions == nil {
		o.identityOptions = identityclient.NewOptions()
	}

	if o.regionOptions == nil {
		o.regionOptions = regionclient.NewOptions()
	}

	o.identityOptions.AddFlags(f)
	o.regionOptions.AddFlags(f)
	o.clientOptions.AddFlags(f)
}

// Provisioner encapsulates control plane provisioning.
type Provisioner struct {
	provisioners.Metadata

	// cluster is the compute cluster we're provisioning.
	cluster unikornv1.ComputeCluster

	// options are documented for the type.
	options *Options

	// needsRetry informs whether we need to trigger another reconcile.
	needsRetry bool
}

// New returns a new initialized provisioner object.
func New(options manager.ControllerOptions) provisioners.ManagerProvisioner {
	o, _ := options.(*Options)

	return &Provisioner{
		options: o,
	}
}

// Ensure the ManagerProvisioner interface is implemented.
var _ provisioners.ManagerProvisioner = &Provisioner{}

func (p *Provisioner) Object() unikornv1core.ManagableResourceInterface {
	return &p.cluster
}

// openstackIdentityStatus are acquired from the region controller at
// reconcile time as the identity provisioning is asynchronous.
type openstackIdentityStatus struct {
	// SSHPrivateKey that has been provisioned for the cluster.
	SSHPrivateKey *string
	// NetworkID is the network to use for provisioning the cluster on.
	// This is typically used to pass in bare-metal provider networks.
	NetworkID string
}

// getOpenstackIdentityStatus collates a set of credentials and options from the identity and
// network to pass to the resource provisioners.
func (p *Provisioner) getOpenstackIdentityStatus(ctx context.Context, client regionapi.ClientWithResponsesInterface) (*openstackIdentityStatus, error) {
	identity, err := p.getIdentity(ctx, client)
	if err != nil {
		return nil, err
	}

	network, err := p.getNetwork(ctx, client)
	if err != nil {
		return nil, err
	}

	options := &openstackIdentityStatus{
		SSHPrivateKey: identity.Spec.Openstack.SshPrivateKey,
		NetworkID:     network.Metadata.Id,
	}

	return options, nil
}

// updateStatus updates the compute cluster status.
func (p *Provisioner) updateStatus(ctx context.Context, servers serverPoolSet, options *openstackIdentityStatus) {
	log := log.FromContext(ctx)

	p.cluster.Status = unikornv1.ComputeClusterStatus{
		SSHPrivateKey: options.SSHPrivateKey,
	}

	for i := range servers {
		if err := p.updateServerStatus(servers[i]); err != nil {
			log.Error(err, "status update error", "server", servers[i].Metadata.Name)
		}
	}

	// Sort the statuses so they have a deterministic order up the stack, especially
	// to things like the UI.
	slices.SortFunc(p.cluster.Status.WorkloadPools, func(a, b unikornv1.WorkloadPoolStatus) int {
		return strings.Compare(a.Name, b.Name)
	})

	for _, pool := range p.cluster.Status.WorkloadPools {
		slices.SortFunc(pool.Machines, func(a, b unikornv1.MachineStatus) int {
			return strings.Compare(a.Hostname, b.Hostname)
		})
	}
}

// provision does what provisioning can and updates the cluster status.
func (p *Provisioner) provision(ctx context.Context) error {
	// Likewise identity creation is provisioned asynchronously as it too takes a
	// long time, epspectially if a physical network is being provisioned and that
	// needs to go out and talk to swiches.
	client, err := p.getRegionClient(ctx, "provision")
	if err != nil {
		return err
	}

	openstackIndentityStatus, err := p.getOpenstackIdentityStatus(ctx, client)
	if err != nil {
		return err
	}

	servers, err := p.newServerSet(ctx, client)
	if err != nil {
		return err
	}

	// The server set will update as we reconcile, ensure we update the status
	// regardless of what happened.
	defer p.updateStatus(ctx, servers, openstackIndentityStatus)

	securityGroups, err := p.newSecurityGroupSet(ctx, client)
	if err != nil {
		return err
	}

	// Reset the status it'll get updated as we go along...
	p.cluster.Status = unikornv1.ComputeClusterStatus{
		SSHPrivateKey: openstackIndentityStatus.SSHPrivateKey,
	}

	if err := p.reconcileSecurityGroups(ctx, client, securityGroups); err != nil {
		return err
	}

	if err := p.reconcileServers(ctx, client, servers, securityGroups, openstackIndentityStatus); err != nil {
		return err
	}

	return nil
}

// Provision implements the Provision interface.
func (p *Provisioner) Provision(ctx context.Context) error {
	if err := p.provision(ctx); err != nil {
		return err
	}

	if p.needsRetry {
		return provisioners.ErrYield
	}

	return nil
}

// Deprovision implements the Provision interface.
func (p *Provisioner) Deprovision(ctx context.Context) error {
	// Clean up the identity when everything has cleanly deprovisioned.
	// An accepted status means the API has recoded the deletion event and
	// we can delete the cluster, a not found means it's been deleted already
	// and again can proceed.  The goal here is not to leak resources.
	client, err := p.getRegionClient(ctx, "deprovision")
	if err != nil {
		return err
	}

	if err := p.deleteIdentity(ctx, client); err != nil {
		return err
	}

	return nil
}
