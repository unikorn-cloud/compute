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
	"errors"
	"fmt"
	"net/http"

	unikornv1 "github.com/unikorn-cloud/compute/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/compute/pkg/constants"
	"github.com/unikorn-cloud/compute/pkg/provisioners/managers/cluster/util"
	coreclient "github.com/unikorn-cloud/core/pkg/client"
	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	coreapiutils "github.com/unikorn-cloud/core/pkg/util/api"
	identityclient "github.com/unikorn-cloud/identity/pkg/client"
	regionclient "github.com/unikorn-cloud/region/pkg/client"
	regionapi "github.com/unikorn-cloud/region/pkg/openapi"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

var (
	// ErrConsistency is raised when a resource is in a state that is inconsistent
	// with what we expect.
	ErrConsistency = errors.New("consistency error")
)

// Checker updates compute cluster health asynchrounously.
type Checker struct {
	// client is a Kubernetes client.
	client client.Client
	// identityOptions allow the identity host and CA to be set.
	identityOptions *identityclient.Options
	// regionOptions allows the region host and CA to be set.
	regionOptions *regionclient.Options
	// clientOptions give access to client certificate information as
	// we need to talk to identity to get a token, and then to region
	// to ensure cloud identities and networks are provisioned, as well
	// as deptovisioning them.
	clientOptions *coreclient.HTTPClientOptions
}

// New create a checker.
func New(client client.Client, identityOptions *identityclient.Options, regionOptions *regionclient.Options, clientOptions *coreclient.HTTPClientOptions) *Checker {
	return &Checker{
		client:          client,
		identityOptions: identityOptions,
		regionOptions:   regionOptions,
		clientOptions:   clientOptions,
	}
}

// getRegionClient returns an authenticated client.
// TODO: the client should be cached for an appropriate period to avoid polluting the
// caches in identity with new tokens during busy periods.
func (c *Checker) getRegionClient(ctx context.Context) (regionapi.ClientWithResponsesInterface, error) {
	tokenIssuer := identityclient.NewTokenIssuer(c.client, c.identityOptions, c.clientOptions, constants.Application, constants.Version)

	token, err := tokenIssuer.Issue(ctx, "compute-monitor")
	if err != nil {
		return nil, err
	}

	getter := regionclient.New(c.client, c.regionOptions, c.clientOptions)

	client, err := getter.APIClient(ctx, token)
	if err != nil {
		return nil, err
	}

	return client, nil
}

// listServers grabs a list of servers for the cluster.
func listServers(ctx context.Context, cluster *unikornv1.ComputeCluster, region regionapi.ClientWithResponsesInterface) (regionapi.ServersResponse, error) {
	organizationID, ok := cluster.Labels[coreconstants.OrganizationLabel]
	if !ok {
		return nil, fmt.Errorf("%w: cluster %s missing organization label", ErrConsistency, cluster.Name)
	}

	params := &regionapi.GetApiV1OrganizationsOrganizationIDServersParams{
		Tag: util.ClusterTagSelector(cluster),
	}

	response, err := region.GetApiV1OrganizationsOrganizationIDServersWithResponse(ctx, organizationID, params)
	if err != nil {
		return nil, err
	}

	if response.StatusCode() != http.StatusOK {
		return nil, coreapiutils.ExtractError(response.StatusCode(), response)
	}

	return *response.JSON200, nil
}

// updateClusterStatus updates cluster and server provisioning and health statuses.
func (c *Checker) updateClusterStatus(ctx context.Context, cluster *unikornv1.ComputeCluster, region regionapi.ClientWithResponsesInterface) error {
	log := log.FromContext(ctx)

	servers, err := listServers(ctx, cluster, region)
	if err != nil {
		return err
	}

	log.Info("cluster servers", "cluster", cluster.Name, "servers", servers)

	if _, err := util.UpdateClusterStatus(cluster, servers); err != nil {
		return err
	}

	return nil
}

// checkCluster processes a single cluster.
func (c *Checker) checkCluster(ctx context.Context, cluster *unikornv1.ComputeCluster, region regionapi.ClientWithResponsesInterface) error {
	log := log.FromContext(ctx)

	log.Info("updating cluster status", "cluster", cluster.Name)

	updated := cluster.DeepCopy()

	if err := c.updateClusterStatus(ctx, updated, region); err != nil {
		return err
	}

	if err := c.client.Status().Patch(ctx, updated, client.MergeFrom(cluster)); err != nil {
		return err
	}

	return nil
}

// Check implements the monitor Checker interface.
func (c *Checker) Check(ctx context.Context) error {
	clusters := &unikornv1.ComputeClusterList{}

	if err := c.client.List(ctx, clusters, &client.ListOptions{}); err != nil {
		return err
	}

	// Create a region API client.
	region, err := c.getRegionClient(ctx)
	if err != nil {
		return err
	}

	for i := range clusters.Items {
		if err := c.checkCluster(ctx, &clusters.Items[i], region); err != nil {
			return err
		}
	}

	return nil
}
