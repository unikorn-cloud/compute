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
	goerrors "errors"
	"fmt"
	"net"
	"net/http"
	"slices"
	"strings"

	"github.com/spf13/pflag"

	unikornv1 "github.com/unikorn-cloud/compute/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/compute/pkg/openapi"
	"github.com/unikorn-cloud/compute/pkg/server/handler/common"
	"github.com/unikorn-cloud/compute/pkg/server/handler/region"
	"github.com/unikorn-cloud/core/pkg/constants"
	coreapi "github.com/unikorn-cloud/core/pkg/openapi"
	"github.com/unikorn-cloud/core/pkg/server/conversion"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	regionapi "github.com/unikorn-cloud/region/pkg/openapi"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
	"k8s.io/utils/ptr"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	ErrConsistency = goerrors.New("consistency error")

	ErrAPI = goerrors.New("remote api error")
)

type Options struct {
	NodeNetwork    net.IPNet
	DNSNameservers []net.IP
}

func (o *Options) AddFlags(f *pflag.FlagSet) {
	_, nodeNetwork, _ := net.ParseCIDR("192.168.0.0/24")

	dnsNameservers := []net.IP{net.ParseIP("8.8.8.8")}

	f.IPNetVar(&o.NodeNetwork, "default-node-network", *nodeNetwork, "Default node network to use when creating a cluster")
	f.IPSliceVar(&o.DNSNameservers, "default-dns-nameservers", dnsNameservers, "Default DNS nameserver to use when creating a cluster")
}

// Client wraps up cluster related management handling.
type Client struct {
	// client allows Compute API access.
	client client.Client

	// namespace the controller runs in.
	namespace string

	// options control various defaults and the like.
	options *Options

	// identity is a client to access the identity service.
	identity identityapi.ClientWithResponsesInterface

	// region is a client to access regions.
	region regionapi.ClientWithResponsesInterface
}

// NewClient returns a new client with required parameters.
func NewClient(client client.Client, namespace string, options *Options, identity identityapi.ClientWithResponsesInterface, region regionapi.ClientWithResponsesInterface) *Client {
	return &Client{
		client:    client,
		namespace: namespace,
		options:   options,
		identity:  identity,
		region:    region,
	}
}

// List returns all clusters owned by the implicit control plane.
func (c *Client) List(ctx context.Context, organizationID string) (openapi.ComputeClusters, error) {
	requirement, err := labels.NewRequirement(constants.OrganizationLabel, selection.Equals, []string{organizationID})
	if err != nil {
		return nil, errors.OAuth2ServerError("failed to build label selector").WithError(err)
	}

	selector := labels.NewSelector()
	selector = selector.Add(*requirement)

	options := &client.ListOptions{
		LabelSelector: selector,
	}

	result := &unikornv1.ComputeClusterList{}

	if err := c.client.List(ctx, result, options); err != nil {
		return nil, errors.OAuth2ServerError("failed to list clusters").WithError(err)
	}

	slices.SortStableFunc(result.Items, func(a, b unikornv1.ComputeCluster) int {
		return strings.Compare(a.Name, b.Name)
	})

	return newGenerator(c.client, c.options, c.region, "", organizationID, "", nil).convertList(result), nil
}

// get returns the cluster.
func (c *Client) get(ctx context.Context, namespace, clusterID string) (*unikornv1.ComputeCluster, error) {
	result := &unikornv1.ComputeCluster{}

	if err := c.client.Get(ctx, client.ObjectKey{Namespace: namespace, Name: clusterID}, result); err != nil {
		if kerrors.IsNotFound(err) {
			return nil, errors.HTTPNotFound().WithError(err)
		}

		return nil, errors.OAuth2ServerError("unable to get cluster").WithError(err)
	}

	return result, nil
}

func (c *Client) generateAllocations(ctx context.Context, organizationID string, resource *unikornv1.ComputeCluster) (*identityapi.AllocationWrite, error) {
	flavors, err := region.Flavors(ctx, c.region, organizationID, resource.Spec.RegionID)
	if err != nil {
		return nil, err
	}

	var serversCommitted int

	var gpusCommitted int

	// NOTE: the control plane is "free".
	for _, pool := range resource.Spec.WorkloadPools.Pools {
		serversMinimum := *pool.Replicas

		serversCommitted += serversMinimum

		flavorByID := func(f regionapi.Flavor) bool {
			return f.Metadata.Id == *pool.FlavorID
		}

		index := slices.IndexFunc(flavors, flavorByID)
		if index < 0 {
			return nil, fmt.Errorf("%w: flavorID does not exist", ErrConsistency)
		}

		flavor := flavors[index]

		if flavor.Spec.Gpu != nil {
			gpusCommitted += serversMinimum * flavor.Spec.Gpu.PhysicalCount
		}
	}

	request := &identityapi.AllocationWrite{
		Metadata: coreapi.ResourceWriteMetadata{
			Name: constants.UndefinedName,
		},
		Spec: identityapi.AllocationSpec{
			Kind: "kubernetescluster",
			Id:   resource.Name,
			Allocations: identityapi.ResourceAllocationList{
				{
					Kind:      "clusters",
					Committed: 1,
					Reserved:  0,
				},
				{
					Kind:      "servers",
					Committed: serversCommitted,
					Reserved:  0,
				},
				{
					Kind:      "gpus",
					Committed: gpusCommitted,
					Reserved:  0,
				},
			},
		},
	}

	return request, nil
}

func (c *Client) createAllocation(ctx context.Context, organizationID, projectID string, resource *unikornv1.ComputeCluster) (*identityapi.AllocationRead, error) {
	allocations, err := c.generateAllocations(ctx, organizationID, resource)
	if err != nil {
		return nil, err
	}

	resp, err := c.identity.PostApiV1OrganizationsOrganizationIDProjectsProjectIDAllocationsWithResponse(ctx, organizationID, projectID, *allocations)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode() != http.StatusCreated {
		return nil, fmt.Errorf("%w: unexpected status code %d", ErrAPI, resp.StatusCode())
	}

	return resp.JSON201, nil
}

func (c *Client) updateAllocation(ctx context.Context, organizationID, projectID string, resource *unikornv1.ComputeCluster) error {
	allocations, err := c.generateAllocations(ctx, organizationID, resource)
	if err != nil {
		return err
	}

	resp, err := c.identity.PutApiV1OrganizationsOrganizationIDProjectsProjectIDAllocationsAllocationIDWithResponse(ctx, organizationID, projectID, resource.Annotations[constants.AllocationAnnotation], *allocations)
	if err != nil {
		return err
	}

	if resp.StatusCode() != http.StatusOK {
		return fmt.Errorf("%w: unexpected status code %d", ErrAPI, resp.StatusCode())
	}

	return nil
}

func (c *Client) deleteAllocation(ctx context.Context, organizationID, projectID, allocationID string) error {
	resp, err := c.identity.DeleteApiV1OrganizationsOrganizationIDProjectsProjectIDAllocationsAllocationIDWithResponse(ctx, organizationID, projectID, allocationID)
	if err != nil {
		return err
	}

	if resp.StatusCode() != http.StatusAccepted {
		return fmt.Errorf("%w: unexpected status code %d", ErrAPI, resp.StatusCode())
	}

	return nil
}

func (c *Client) createIdentity(ctx context.Context, organizationID, projectID, regionID, clusterID string) (*regionapi.IdentityRead, error) {
	tags := coreapi.TagList{
		coreapi.Tag{
			Name:  constants.ComputeClusterLabel,
			Value: clusterID,
		},
	}

	request := regionapi.PostApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesJSONRequestBody{
		Metadata: coreapi.ResourceWriteMetadata{
			Name:        "compute-cluster-" + clusterID,
			Description: ptr.To("Identity for Compute cluster " + clusterID),
			Tags:        &tags,
		},
		Spec: regionapi.IdentityWriteSpec{
			RegionId: regionID,
		},
	}

	resp, err := c.region.PostApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesWithResponse(ctx, organizationID, projectID, request)
	if err != nil {
		return nil, errors.OAuth2ServerError("unable to create identity").WithError(err)
	}

	if resp.StatusCode() != http.StatusCreated {
		return nil, errors.OAuth2ServerError("unable to create identity")
	}

	return resp.JSON201, nil
}

func (c *Client) createNetworkOpenstack(ctx context.Context, organizationID, projectID string, cluster *unikornv1.ComputeCluster, identity *regionapi.IdentityRead) (*regionapi.NetworkRead, error) {
	tags := coreapi.TagList{
		coreapi.Tag{
			Name:  constants.ComputeClusterLabel,
			Value: cluster.Name,
		},
	}

	dnsNameservers := make([]string, len(cluster.Spec.Network.DNSNameservers))

	for i, ip := range cluster.Spec.Network.DNSNameservers {
		dnsNameservers[i] = ip.String()
	}

	request := regionapi.NetworkWrite{
		Metadata: coreapi.ResourceWriteMetadata{
			Name:        "compute-cluster-" + cluster.Name,
			Description: ptr.To("Network for cluster " + cluster.Name),
			Tags:        &tags,
		},
		Spec: &regionapi.NetworkWriteSpec{
			Prefix:         cluster.Spec.Network.NodeNetwork.String(),
			DnsNameservers: dnsNameservers,
		},
	}

	resp, err := c.region.PostApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDNetworksWithResponse(ctx, organizationID, projectID, identity.Metadata.Id, request)
	if err != nil {
		return nil, errors.OAuth2ServerError("unable to create network").WithError(err)
	}

	if resp.StatusCode() != http.StatusCreated {
		return nil, errors.OAuth2ServerError("unable to create network")
	}

	return resp.JSON201, nil
}

func (c *Client) applyCloudSpecificConfiguration(ctx context.Context, organizationID, projectID string, allocation *identityapi.AllocationRead, identity *regionapi.IdentityRead, cluster *unikornv1.ComputeCluster) error {
	// Save the identity ID for later cleanup.
	if cluster.Annotations == nil {
		cluster.Annotations = map[string]string{}
	}

	cluster.Annotations[constants.AllocationAnnotation] = allocation.Metadata.Id
	cluster.Annotations[constants.IdentityAnnotation] = identity.Metadata.Id

	// Provision a network for nodes to attach to.
	network, err := c.createNetworkOpenstack(ctx, organizationID, projectID, cluster, identity)
	if err != nil {
		return errors.OAuth2ServerError("failed to create physical network").WithError(err)
	}

	cluster.Annotations[constants.PhysicalNetworkAnnotation] = network.Metadata.Id

	return nil
}

func preserveAnnotations(requested, current *unikornv1.ComputeCluster) error {
	identity, ok := current.Annotations[constants.IdentityAnnotation]
	if !ok {
		return fmt.Errorf("%w: identity annotation missing", ErrConsistency)
	}

	allocation, ok := current.Annotations[constants.AllocationAnnotation]
	if !ok {
		return fmt.Errorf("%w: allocation annotation missing", ErrConsistency)
	}

	network, ok := current.Annotations[constants.PhysicalNetworkAnnotation]
	if !ok {
		return fmt.Errorf("%w: network annotation missing", ErrConsistency)
	}

	if requested.Annotations == nil {
		requested.Annotations = map[string]string{}
	}

	requested.Annotations[constants.IdentityAnnotation] = identity
	requested.Annotations[constants.AllocationAnnotation] = allocation
	requested.Annotations[constants.PhysicalNetworkAnnotation] = network

	return nil
}

// Create creates the implicit cluster indentified by the JTW claims.
func (c *Client) Create(ctx context.Context, organizationID, projectID string, request *openapi.ComputeClusterWrite) (*openapi.ComputeClusterRead, error) {
	namespace, err := common.New(c.client).ProjectNamespace(ctx, organizationID, projectID)
	if err != nil {
		return nil, err
	}

	cluster, err := newGenerator(c.client, c.options, c.region, namespace.Name, organizationID, projectID, nil).generate(ctx, request)
	if err != nil {
		return nil, err
	}

	allocation, err := c.createAllocation(ctx, organizationID, projectID, cluster)
	if err != nil {
		return nil, errors.OAuth2ServerError("failed to create quota allocation").WithError(err)
	}

	identity, err := c.createIdentity(ctx, organizationID, projectID, request.Spec.RegionId, cluster.Name)
	if err != nil {
		return nil, err
	}

	if err := c.applyCloudSpecificConfiguration(ctx, organizationID, projectID, allocation, identity, cluster); err != nil {
		return nil, err
	}

	if err := c.client.Create(ctx, cluster); err != nil {
		return nil, errors.OAuth2ServerError("failed to create cluster").WithError(err)
	}

	return newGenerator(c.client, c.options, c.region, "", organizationID, "", nil).convert(cluster), nil
}

// Delete deletes the implicit cluster indentified by the JTW claims.
func (c *Client) Delete(ctx context.Context, organizationID, projectID, clusterID string) error {
	namespace, err := common.New(c.client).ProjectNamespace(ctx, organizationID, projectID)
	if err != nil {
		return err
	}

	cluster, err := c.get(ctx, namespace.Name, clusterID)
	if err != nil {
		if kerrors.IsNotFound(err) {
			return errors.HTTPNotFound().WithError(err)
		}

		return errors.OAuth2ServerError("failed to get cluster").WithError(err)
	}

	if err := c.client.Delete(ctx, cluster); err != nil {
		return errors.OAuth2ServerError("failed to delete cluster").WithError(err)
	}

	if err := c.deleteAllocation(ctx, organizationID, projectID, cluster.Annotations[constants.AllocationAnnotation]); err != nil {
		return errors.OAuth2ServerError("failed to delete quota allocation").WithError(err)
	}

	return nil
}

// Update implements read/modify/write for the cluster.
func (c *Client) Update(ctx context.Context, organizationID, projectID, clusterID string, request *openapi.ComputeClusterWrite) error {
	namespace, err := common.New(c.client).ProjectNamespace(ctx, organizationID, projectID)
	if err != nil {
		return err
	}

	if namespace.DeletionTimestamp != nil {
		return errors.OAuth2InvalidRequest("control plane is being deleted")
	}

	current, err := c.get(ctx, namespace.Name, clusterID)
	if err != nil {
		return err
	}

	required, err := newGenerator(c.client, c.options, c.region, namespace.Name, organizationID, projectID, current).generate(ctx, request)
	if err != nil {
		return err
	}

	if err := conversion.UpdateObjectMetadata(required, current, []string{constants.IdentityAnnotation}, []string{constants.PhysicalNetworkAnnotation}); err != nil {
		return errors.OAuth2ServerError("failed to merge metadata").WithError(err)
	}

	if err := preserveAnnotations(required, current); err != nil {
		return errors.OAuth2ServerError("failed to merge annotations").WithError(err)
	}

	if err := c.updateAllocation(ctx, organizationID, projectID, required); err != nil {
		return errors.OAuth2ServerError("failed to update quota allocation").WithError(err)
	}

	// Experience has taught me that modifying caches by accident is a bad thing
	// so be extra safe and deep copy the existing resource.
	updated := current.DeepCopy()
	updated.Labels = required.Labels
	updated.Annotations = required.Annotations
	updated.Spec = required.Spec

	if err := c.client.Patch(ctx, updated, client.MergeFrom(current)); err != nil {
		return errors.OAuth2ServerError("failed to patch cluster").WithError(err)
	}

	return nil
}
