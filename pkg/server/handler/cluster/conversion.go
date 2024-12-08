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
	goerrors "errors"
	"fmt"
	"net"
	"net/http"
	"slices"

	unikornv1 "github.com/unikorn-cloud/compute/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/compute/pkg/openapi"
	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreerrors "github.com/unikorn-cloud/core/pkg/errors"
	coreapi "github.com/unikorn-cloud/core/pkg/openapi"
	"github.com/unikorn-cloud/core/pkg/server/conversion"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/core/pkg/util"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	regionapi "github.com/unikorn-cloud/region/pkg/openapi"

	"k8s.io/utils/ptr"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	ErrResourceLookup = goerrors.New("could not find the requested resource")
)

// generator wraps up the myriad things we need to pass around as an object
// rather than a whole bunch of arguments.
type generator struct {
	// client allows Compute access.
	client client.Client
	// options allows access to resource defaults.
	options *Options
	// region is a client to access regions.
	region regionapi.ClientWithResponsesInterface
	// namespace the resource is provisioned in.
	namespace string
	// organizationID is the unique organization identifier.
	organizationID string
	// projectID is the unique project identifier.
	projectID string
	// current is the current state of the resource.
	current *unikornv1.ComputeCluster
}

func newGenerator(client client.Client, options *Options, region regionapi.ClientWithResponsesInterface, namespace, organizationID, projectID string, current *unikornv1.ComputeCluster) *generator {
	return &generator{
		client:         client,
		options:        options,
		region:         region,
		namespace:      namespace,
		organizationID: organizationID,
		projectID:      projectID,
		current:        current,
	}
}

func (g *generator) getImage(ctx context.Context, regionID, imageID string) (*regionapi.Image, error) {
	resp, err := g.region.GetApiV1OrganizationsOrganizationIDRegionsRegionIDImagesWithResponse(ctx, g.organizationID, regionID)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode() != http.StatusOK {
		return nil, errors.OAuth2ServerError("failed to list images")
	}

	images := *resp.JSON200

	for i := range images {
		if images[i].Metadata.Id == imageID {
			return &images[i], nil
		}
	}

	return nil, errors.OAuth2ServerError("failed to lookup image id")
}

// convertMachine converts from a custom resource into the API definition.
func (g *generator) convertMachine(ctx context.Context, in *unikornv1.ComputeWorkloadPoolSpec, cluster *unikornv1.ComputeCluster) (*openapi.MachinePool, error) {
	image, err := g.getImage(ctx, cluster.Spec.RegionID, *in.ImageID)
	if err != nil {
		return nil, err
	}

	machine := &openapi.MachinePool{
		Replicas:           *in.Replicas,
		FlavorId:           *in.FlavorID,
		PublicIPAllocation: convertPublicIPAllocation(in.PublicIPAllocation),
		Firewall:           convertFirewall(in.Firewall),
		Image: openapi.ImageSelector{
			Distro:  image.Spec.Os.Distro,
			Variant: image.Spec.Os.Variant,
			Version: ptr.To(image.Spec.Os.Version),
		},
		UserData: convertUserData(in.UserData),
	}

	return machine, nil
}

// convertUserData converts from a custom resource into the API definition.
func convertUserData(in []byte) *[]byte {
	if in == nil {
		return nil
	}

	return &in
}

// convertFirewall converts from a custom resource into the API definition.
func convertFirewall(in *unikornv1.FirewallSpec) *openapi.Firewall {
	if in == nil || len(in.Ingress) == 0 {
		return nil
	}

	// Map to hold the grouped results with a composite key
	grouped := make(map[string]*openapi.FirewallRule)

	for _, ingress := range in.Ingress {
		key := fmt.Sprintf("%s-%s", ingress.Protocol, ingress.Port.String())

		if _, exists := grouped[key]; !exists {
			grouped[key] = &openapi.FirewallRule{
				Protocol: convertProtocol(ingress.Protocol),
				Port:     convertPort(ingress.Port),
				Cidr:     []string{ingress.CIDR.String()},
			}
		} else {
			grouped[key].Cidr = append(grouped[key].Cidr, ingress.CIDR.String())
		}
	}

	ingress := []openapi.FirewallRule{}
	for _, rule := range grouped {
		ingress = append(ingress, *rule)
	}

	return &openapi.Firewall{
		Ingress: &ingress,
	}
}

// convertProtocol converts from a custom resource into the API definition.
func convertProtocol(in unikornv1.FirewallRuleProtocol) openapi.FirewallRuleProtocol {
	var out openapi.FirewallRuleProtocol

	switch in {
	case unikornv1.TCP:
		out = openapi.Tcp
	case unikornv1.UDP:
		out = openapi.Udp
	}

	return out
}

// convertPort converts from a custom resource into the API definition.
func convertPort(in unikornv1.FirewallRulePort) openapi.FirewallRulePort {
	return openapi.FirewallRulePort{
		Number: in.Number,
		Range:  convertPortRange(in.Range),
	}
}

// convertPortRange converts from a custom resource into the API definition.
func convertPortRange(in *unikornv1.FirewallRulePortRange) *openapi.FirewallRulePortRange {
	if in == nil {
		return nil
	}

	return &openapi.FirewallRulePortRange{
		Start: in.Start,
		End:   in.End,
	}
}

// convertPublicIPAllocation converts from a custom resource into the API definition.
func convertPublicIPAllocation(in *unikornv1.PublicIPAllocationSpec) *openapi.PublicIPAllocation {
	if in == nil {
		return nil
	}

	return &openapi.PublicIPAllocation{
		Enabled: in.Enabled,
	}
}

// convertWorkloadPool converts from a custom resource into the API definition.
func (g *generator) convertWorkloadPool(ctx context.Context, in *unikornv1.ComputeClusterWorkloadPoolsPoolSpec, cluster *unikornv1.ComputeCluster) (*openapi.ComputeClusterWorkloadPool, error) {
	machine, err := g.convertMachine(ctx, &in.ComputeWorkloadPoolSpec, cluster)
	if err != nil {
		return nil, err
	}

	workloadPool := &openapi.ComputeClusterWorkloadPool{
		Name:    in.Name,
		Machine: *machine,
	}

	return workloadPool, nil
}

// convertWorkloadPools converts from a custom resource into the API definition.
func (g *generator) convertWorkloadPools(ctx context.Context, in *unikornv1.ComputeCluster) ([]openapi.ComputeClusterWorkloadPool, error) {
	workloadPools := make([]openapi.ComputeClusterWorkloadPool, len(in.Spec.WorkloadPools.Pools))

	for i := range in.Spec.WorkloadPools.Pools {
		pool, err := g.convertWorkloadPool(ctx, &in.Spec.WorkloadPools.Pools[i], in)
		if err != nil {
			return nil, err
		}

		workloadPools[i] = *pool
	}

	return workloadPools, nil
}

func convertCondition(in unikornv1core.ConditionReason) coreapi.ResourceProvisioningStatus {
	//nolint:exhaustive
	switch in {
	case unikornv1core.ConditionReasonDeprovisioning:
		return coreapi.ResourceProvisioningStatusDeprovisioning
	case unikornv1core.ConditionReasonErrored:
		return coreapi.ResourceProvisioningStatusError
	case unikornv1core.ConditionReasonProvisioned:
		return coreapi.ResourceProvisioningStatusProvisioned
	case unikornv1core.ConditionReasonProvisioning:
		return coreapi.ResourceProvisioningStatusProvisioning
	}

	return coreapi.ResourceProvisioningStatusUnknown
}

func convertMachineStatus(in *unikornv1.MachineStatus) *openapi.ComputeClusterMachineStatus {
	status := coreapi.ResourceProvisioningStatusUnknown

	if condition, err := unikornv1core.GetCondition(in.Conditions, unikornv1core.ConditionAvailable); err == nil {
		status = convertCondition(condition.Reason)
	}

	out := &openapi.ComputeClusterMachineStatus{
		Hostname:  in.Hostname,
		PrivateIP: in.PrivateIP,
		PublicIP:  in.PublicIP,
		Status:    status,
	}

	return out
}

func convertMachinesStatus(in []unikornv1.MachineStatus) *openapi.ComputeClusterMachinesStatus {
	out := make(openapi.ComputeClusterMachinesStatus, len(in))

	for i := range in {
		out[i] = *convertMachineStatus(&in[i])
	}

	return &out
}

func convertWorkloadPoolStatus(in *unikornv1.WorkloadPoolStatus) *openapi.ComputeClusterWorkloadPoolStatus {
	out := &openapi.ComputeClusterWorkloadPoolStatus{
		Name:     in.Name,
		Replicas: in.Replicas,
		Machines: convertMachinesStatus(in.Machines),
	}

	return out
}

func convertWorkloadPoolsStatus(in []unikornv1.WorkloadPoolStatus) *openapi.ComputeClusterWorkloadPoolsStatus {
	out := make(openapi.ComputeClusterWorkloadPoolsStatus, len(in))

	for i := range in {
		out[i] = *convertWorkloadPoolStatus(&in[i])
	}

	return &out
}

func convertClusterStatus(in *unikornv1.ComputeClusterStatus) *openapi.ComputeClusterStatus {
	if in == nil {
		return nil
	}

	out := &openapi.ComputeClusterStatus{
		WorkloadPools: convertWorkloadPoolsStatus(in.WorkloadPools),
	}

	return out
}

// convert converts from a custom resource into the API definition.
func (g *generator) convert(ctx context.Context, in *unikornv1.ComputeCluster) (*openapi.ComputeClusterRead, error) {
	provisioningStatus := coreapi.ResourceProvisioningStatusUnknown

	if condition, err := in.StatusConditionRead(unikornv1core.ConditionAvailable); err == nil {
		provisioningStatus = conversion.ConvertStatusCondition(condition)
	}

	pools, err := g.convertWorkloadPools(ctx, in)
	if err != nil {
		return nil, err
	}

	out := &openapi.ComputeClusterRead{
		Metadata: conversion.ProjectScopedResourceReadMetadata(in, in.Spec.Tags, provisioningStatus),
		Spec: openapi.ComputeClusterSpec{
			RegionId:      in.Spec.RegionID,
			WorkloadPools: pools,
		},
		Status: convertClusterStatus(&in.Status),
	}

	return out, nil
}

// uconvertList converts from a custom resource list into the API definition.
func (g *generator) convertList(ctx context.Context, in *unikornv1.ComputeClusterList) (openapi.ComputeClusters, error) {
	out := make(openapi.ComputeClusters, len(in.Items))

	for i := range in.Items {
		cluster, err := g.convert(ctx, &in.Items[i])
		if err != nil {
			return nil, err
		}

		out[i] = *cluster
	}

	return out, nil
}

// chooseImages returns an image for the requested machine and flavor.
func (g *generator) chooseImage(ctx context.Context, request *openapi.ComputeClusterWrite, m *openapi.MachinePool, _ *regionapi.Flavor) (*regionapi.Image, error) {
	resp, err := g.region.GetApiV1OrganizationsOrganizationIDRegionsRegionIDImagesWithResponse(ctx, g.organizationID, request.Spec.RegionId)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode() != http.StatusOK {
		return nil, errors.OAuth2ServerError("failed to list images")
	}

	images := *resp.JSON200

	// TODO: is the image compatible with the flavor virtualization type???
	images = slices.DeleteFunc(images, func(image regionapi.Image) bool {
		// Is it the right distro?
		if image.Spec.Os.Distro != m.Image.Distro {
			return true
		}

		// Is it the right variant?
		if m.Image.Variant != nil {
			if image.Spec.Os.Variant == nil {
				return true
			}

			if *m.Image.Variant != *image.Spec.Os.Variant {
				return true
			}
		}

		// Is it the right version?
		if m.Image.Version != nil {
			if *m.Image.Version != image.Spec.Os.Version {
				return true
			}
		}

		return false
	})

	if len(images) == 0 {
		return nil, errors.OAuth2ServerError("unable to select an image")
	}

	// Select the most recent, the region servie guarantees temporal ordering.
	return &images[0], nil
}

// generateNetwork generates the network part of a cluster.
func (g *generator) generateNetwork() *unikornv1core.NetworkGeneric {
	// Grab some defaults (as these are in the right format already)
	// the override with anything coming in from the API, if set.
	nodeNetwork := g.options.NodeNetwork
	dnsNameservers := g.options.DNSNameservers

	network := &unikornv1core.NetworkGeneric{
		NodeNetwork:    &unikornv1core.IPv4Prefix{IPNet: nodeNetwork},
		DNSNameservers: unikornv1core.IPv4AddressSliceFromIPSlice(dnsNameservers),
	}

	return network
}

// generateMachineGeneric generates a generic machine part of the cluster.
func (g *generator) generateMachineGeneric(ctx context.Context, request *openapi.ComputeClusterWrite, m *openapi.MachinePool, flavor *regionapi.Flavor) (*unikornv1core.MachineGeneric, error) {
	image, err := g.chooseImage(ctx, request, m, flavor)
	if err != nil {
		return nil, err
	}

	machine := &unikornv1core.MachineGeneric{
		Replicas: &m.Replicas,
		ImageID:  ptr.To(image.Metadata.Id),
		FlavorID: &flavor.Metadata.Id,
	}

	return machine, nil
}

// generateWorkloadPools generates the workload pools part of a cluster.
func (g *generator) generateWorkloadPools(ctx context.Context, request *openapi.ComputeClusterWrite) (*unikornv1.ComputeClusterWorkloadPoolsSpec, error) {
	workloadPools := &unikornv1.ComputeClusterWorkloadPoolsSpec{}

	for i := range request.Spec.WorkloadPools {
		pool := &request.Spec.WorkloadPools[i]

		flavor, err := g.lookupFlavor(ctx, request, pool.Machine.FlavorId)
		if err != nil {
			return nil, err
		}

		machine, err := g.generateMachineGeneric(ctx, request, &pool.Machine, flavor)
		if err != nil {
			return nil, err
		}

		var firewall *unikornv1.FirewallSpec
		if pool.Machine.Firewall != nil && pool.Machine.Firewall.Ingress != nil {
			firewall, err = g.generateFirewall(pool)
			if err != nil {
				return nil, err
			}
		}

		workloadPool := unikornv1.ComputeClusterWorkloadPoolsPoolSpec{
			ComputeWorkloadPoolSpec: unikornv1.ComputeWorkloadPoolSpec{
				Name:               pool.Name,
				MachineGeneric:     *machine,
				PublicIPAllocation: g.generatePublicIPAllocation(pool),
				Firewall:           firewall,
				UserData:           g.generateUserData(pool.Machine.UserData),
			},
		}

		workloadPools.Pools = append(workloadPools.Pools, workloadPool)
	}

	return workloadPools, nil
}

// generatePublicIPAllocation generates the public IP allocation part of a workload pool.
func (g *generator) generatePublicIPAllocation(request *openapi.ComputeClusterWorkloadPool) *unikornv1.PublicIPAllocationSpec {
	if request.Machine.PublicIPAllocation == nil {
		return nil
	}

	return &unikornv1.PublicIPAllocationSpec{
		Enabled: request.Machine.PublicIPAllocation.Enabled,
	}
}

func (g *generator) generateUserData(data *[]byte) []byte {
	if data == nil {
		return nil
	}

	return *data
}

func (g *generator) generateFirewall(request *openapi.ComputeClusterWorkloadPool) (*unikornv1.FirewallSpec, error) {
	firewall := &unikornv1.FirewallSpec{
		Ingress: []unikornv1.FirewallRule{},
	}

	for _, ingress := range *request.Machine.Firewall.Ingress {
		for _, cidr := range ingress.Cidr {
			_, prefix, err := net.ParseCIDR(cidr)
			if err != nil {
				return nil, err
			}

			rule := unikornv1.FirewallRule{
				ID:       g.firewallRuleID(request.Name, ingress.Protocol, &ingress.Port, cidr),
				Protocol: g.generateFirewallRuleProtocol(ingress.Protocol),
				Port:     g.generateFirewallPort(&ingress.Port),
				CIDR: unikornv1core.IPv4Prefix{
					IPNet: *prefix,
				},
			}

			firewall.Ingress = append(firewall.Ingress, rule)
		}
	}

	return firewall, nil
}

func (g *generator) firewallRuleID(poolName string, protocol openapi.FirewallRuleProtocol, port *openapi.FirewallRulePort, cidr string) string {
	pool := g.lookupCurrentPool(poolName)

	if pool == nil || pool.Firewall == nil {
		return util.GenerateResourceID()
	}

	index := slices.IndexFunc(pool.Firewall.Ingress, func(rule unikornv1.FirewallRule) bool {
		return rule.CIDR.String() == cidr && rule.Port.String() == g.generateFirewallRulePortKey(port) && rule.Protocol == unikornv1.FirewallRuleProtocol(protocol)
	})

	if index >= 0 {
		return pool.Firewall.Ingress[index].ID
	}

	return util.GenerateResourceID()
}

func (g *generator) generateFirewallRulePortKey(port *openapi.FirewallRulePort) string {
	if port.Number != nil {
		return fmt.Sprintf("%d", *port.Number)
	}

	return fmt.Sprintf("%d-%d", port.Range.Start, port.Range.End)
}

func (g *generator) lookupCurrentPool(poolName string) *unikornv1.ComputeClusterWorkloadPoolsPoolSpec {
	if g.current == nil {
		return nil
	}

	index := slices.IndexFunc(g.current.Spec.WorkloadPools.Pools, func(wp unikornv1.ComputeClusterWorkloadPoolsPoolSpec) bool {
		return wp.Name == poolName
	})

	if index < 0 {
		return nil
	}

	return &g.current.Spec.WorkloadPools.Pools[index]
}

func (g *generator) generateFirewallRuleProtocol(in openapi.FirewallRuleProtocol) unikornv1.FirewallRuleProtocol {
	var out unikornv1.FirewallRuleProtocol

	switch in {
	case openapi.Tcp:
		out = unikornv1.TCP
	case openapi.Udp:
		out = unikornv1.UDP
	}

	return out
}

func (g *generator) generateFirewallPort(request *openapi.FirewallRulePort) unikornv1.FirewallRulePort {
	return unikornv1.FirewallRulePort{
		Number: request.Number,
		Range:  g.generateFirewallPortRange(request.Range),
	}
}

func (g *generator) generateFirewallPortRange(portrange *openapi.FirewallRulePortRange) *unikornv1.FirewallRulePortRange {
	if portrange == nil {
		return nil
	}

	return &unikornv1.FirewallRulePortRange{
		Start: portrange.Start,
		End:   portrange.End,
	}
}

// lookupFlavor resolves the flavor from its name.
// NOTE: It looks like garbage performance, but the provider should be memoized...
func (g *generator) lookupFlavor(ctx context.Context, request *openapi.ComputeClusterWrite, id string) (*regionapi.Flavor, error) {
	resp, err := g.region.GetApiV1OrganizationsOrganizationIDRegionsRegionIDFlavorsWithResponse(ctx, g.organizationID, request.Spec.RegionId)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode() != http.StatusOK {
		return nil, fmt.Errorf("%w: flavor GET expected 200 got %d", coreerrors.ErrAPIStatus, resp.StatusCode())
	}

	flavors := *resp.JSON200

	index := slices.IndexFunc(flavors, func(flavor regionapi.Flavor) bool {
		return flavor.Metadata.Id == id
	})

	if index < 0 {
		return nil, fmt.Errorf("%w: flavor %s", ErrResourceLookup, id)
	}

	return &flavors[index], nil
}

// generate generates the full cluster custom resource.
// TODO: there are a lot of parameters being passed about, we should make this
// a struct and pass them as a single blob.
func (g *generator) generate(ctx context.Context, request *openapi.ComputeClusterWrite) (*unikornv1.ComputeCluster, error) {
	computeWorkloadPools, err := g.generateWorkloadPools(ctx, request)
	if err != nil {
		return nil, err
	}

	userinfo, err := authorization.UserinfoFromContext(ctx)
	if err != nil {
		return nil, err
	}

	cluster := &unikornv1.ComputeCluster{
		ObjectMeta: conversion.NewObjectMetadata(&request.Metadata, g.namespace, userinfo.Sub).WithOrganization(g.organizationID).WithProject(g.projectID).Get(),
		Spec: unikornv1.ComputeClusterSpec{
			Tags:          conversion.GenerateTagList(request.Metadata.Tags),
			RegionID:      request.Spec.RegionId,
			Network:       g.generateNetwork(),
			WorkloadPools: computeWorkloadPools,
		},
	}

	return cluster, nil
}
