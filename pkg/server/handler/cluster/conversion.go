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

	unikornv1 "github.com/unikorn-cloud/compute/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/compute/pkg/openapi"
	"github.com/unikorn-cloud/compute/pkg/server/handler/region"
	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreapi "github.com/unikorn-cloud/core/pkg/openapi"
	"github.com/unikorn-cloud/core/pkg/server/conversion"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	coreapiutils "github.com/unikorn-cloud/core/pkg/util/api"
	"github.com/unikorn-cloud/identity/pkg/handler/common"
	regionapi "github.com/unikorn-cloud/region/pkg/openapi"

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
	region *region.Client
	// namespace the resource is provisioned in.
	namespace string
	// organizationID is the unique organization identifier.
	organizationID string
	// projectID is the unique project identifier.
	projectID string
	// current is the current state of the resource.
	current *unikornv1.ComputeCluster
}

func newGenerator(client client.Client, options *Options, region *region.Client, namespace, organizationID, projectID string, current *unikornv1.ComputeCluster) *generator {
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

// convertMachine converts from a custom resource into the API definition.
func (g *generator) convertMachine(in *unikornv1.ComputeClusterWorkloadPoolSpec) *openapi.MachinePool {
	return &openapi.MachinePool{
		Replicas:            in.Replicas,
		FlavorId:            in.FlavorID,
		PublicIPAllocation:  convertPublicIPAllocation(in.PublicIPAllocation),
		Firewall:            convertFirewallRules(in.Firewall),
		Image:               convertImage(in),
		UserData:            convertUserData(in.UserData),
		AllowedAddressPairs: convertAllowedAddressPairs(in.AllowedAddressPairs),
	}
}

// convertAllowedAddressPairs converts from a custom resource into the API definition.
func convertAllowedAddressPairs(in []unikornv1.ComputeWorkloadPoolAddressPair) *openapi.AllowedAddressPairList {
	out := make([]openapi.AllowedAddressPair, len(in))

	for i := range in {
		out[i] = openapi.AllowedAddressPair{
			Cidr: in[i].CIDR.String(),
		}

		if in[i].MACAddress != "" {
			out[i].MacAddress = &in[i].MACAddress
		}
	}

	return &out
}

// convertImage converts from a custom resource into the API definition.
func convertImage(in *unikornv1.ComputeClusterWorkloadPoolSpec) openapi.ComputeImage {
	if in.ImageSelector == nil {
		return openapi.ComputeImage{
			Id: &in.ImageID,
		}
	}

	return openapi.ComputeImage{
		Selector: &openapi.ImageSelector{
			Distro:  regionapi.OsDistro(in.ImageSelector.Distro),
			Variant: in.ImageSelector.Variant,
			Version: in.ImageSelector.Version,
		},
	}
}

// convertUserData converts from a custom resource into the API definition.
func convertUserData(in []byte) *[]byte {
	if in == nil {
		return nil
	}

	return &in
}

func convertDirection(in unikornv1.FirewallRuleDirection) openapi.FirewallRuleDirection {
	switch in {
	case unikornv1.Ingress:
		return openapi.Ingress
	case unikornv1.Egress:
		return openapi.Egress
	}

	return ""
}

// convertProtocol converts from a custom resource into the API definition.
func convertProtocol(in unikornv1.FirewallRuleProtocol) openapi.FirewallRuleProtocol {
	switch in {
	case unikornv1.TCP:
		return openapi.Tcp
	case unikornv1.UDP:
		return openapi.Udp
	}

	return ""
}

func convertPrefixes(in []unikornv1core.IPv4Prefix) []string {
	out := make([]string, len(in))

	for i, prefix := range in {
		out[i] = prefix.String()
	}

	return out
}

func convertFirewallRule(in *unikornv1.FirewallRule) *openapi.FirewallRule {
	return &openapi.FirewallRule{
		Direction: convertDirection(in.Direction),
		Protocol:  convertProtocol(in.Protocol),
		Port:      in.Port,
		PortMax:   in.PortMax,
		Prefixes:  convertPrefixes(in.Prefixes),
	}
}

// convertFirewall converts from a custom resource into the API definition.
func convertFirewallRules(in []unikornv1.FirewallRule) *openapi.FirewallRules {
	if len(in) == 0 {
		return nil
	}

	out := make(openapi.FirewallRules, len(in))

	for i := range in {
		out[i] = *convertFirewallRule(&in[i])
	}

	return &out
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
func (g *generator) convertWorkloadPool(in *unikornv1.ComputeClusterWorkloadPoolSpec) *openapi.ComputeClusterWorkloadPool {
	return &openapi.ComputeClusterWorkloadPool{
		Name:    in.Name,
		Machine: *g.convertMachine(in),
	}
}

// convertWorkloadPools converts from a custom resource into the API definition.
func (g *generator) convertWorkloadPools(in *unikornv1.ComputeCluster) []openapi.ComputeClusterWorkloadPool {
	workloadPools := make([]openapi.ComputeClusterWorkloadPool, len(in.Spec.WorkloadPools.Pools))

	for i := range in.Spec.WorkloadPools.Pools {
		workloadPools[i] = *g.convertWorkloadPool(&in.Spec.WorkloadPools.Pools[i])
	}

	return workloadPools
}

//nolint:exhaustive
func convertProvisioningStatus(in unikornv1core.ConditionReason) coreapi.ResourceProvisioningStatus {
	switch in {
	case unikornv1core.ConditionReasonDeprovisioning:
		return coreapi.ResourceProvisioningStatusDeprovisioning
	case unikornv1core.ConditionReasonErrored:
		return coreapi.ResourceProvisioningStatusError
	case unikornv1core.ConditionReasonProvisioned:
		return coreapi.ResourceProvisioningStatusProvisioned
	case unikornv1core.ConditionReasonProvisioning:
		return coreapi.ResourceProvisioningStatusProvisioning
	default:
		return coreapi.ResourceProvisioningStatusUnknown
	}
}

//nolint:exhaustive
func convertHealthStatus(in unikornv1core.ConditionReason) coreapi.ResourceHealthStatus {
	switch in {
	case unikornv1core.ConditionReasonHealthy:
		return coreapi.ResourceHealthStatusHealthy
	case unikornv1core.ConditionReasonDegraded:
		return coreapi.ResourceHealthStatusDegraded
	default:
		return coreapi.ResourceHealthStatusUnknown
	}
}

func convertMachineStatus(in *unikornv1.MachineStatus) *openapi.ComputeClusterMachineStatus {
	provisioningStatus := coreapi.ResourceProvisioningStatusUnknown

	if condition, err := unikornv1core.GetCondition(in.Conditions, unikornv1core.ConditionAvailable); err == nil {
		provisioningStatus = convertProvisioningStatus(condition.Reason)
	}

	healthStatus := coreapi.ResourceHealthStatusUnknown

	if condition, err := unikornv1core.GetCondition(in.Conditions, unikornv1core.ConditionHealthy); err == nil {
		healthStatus = convertHealthStatus(condition.Reason)
	}

	out := &openapi.ComputeClusterMachineStatus{
		Hostname:           in.Hostname,
		FlavorID:           in.FlavorID,
		ImageID:            in.ImageID,
		PrivateIP:          in.PrivateIP,
		PublicIP:           in.PublicIP,
		ProvisioningStatus: provisioningStatus,
		HealthStatus:       healthStatus,
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
		SshPrivateKey: in.SSHPrivateKey,
		WorkloadPools: convertWorkloadPoolsStatus(in.WorkloadPools),
	}

	return out
}

// convert converts from a custom resource into the API definition.
func (g *generator) convert(in *unikornv1.ComputeCluster) *openapi.ComputeClusterRead {
	out := &openapi.ComputeClusterRead{
		Metadata: conversion.ProjectScopedResourceReadMetadata(in, in.Spec.Tags),
		Spec: openapi.ComputeClusterSpec{
			RegionId:      in.Spec.RegionID,
			WorkloadPools: g.convertWorkloadPools(in),
		},
		Status: convertClusterStatus(&in.Status),
	}

	return out
}

// uconvertList converts from a custom resource list into the API definition.
func (g *generator) convertList(in *unikornv1.ComputeClusterList) openapi.ComputeClusters {
	out := make(openapi.ComputeClusters, len(in.Items))

	for i := range in.Items {
		out[i] = *g.convert(&in.Items[i])
	}

	return out
}

// chooseImages returns an image for the requested machine and flavor.
func (g *generator) chooseImage(ctx context.Context, request *openapi.ComputeClusterWrite, m *openapi.MachinePool, _ *regionapi.Flavor) (*regionapi.Image, error) {
	client, err := g.region.Client(ctx)
	if err != nil {
		return nil, err
	}

	resp, err := client.GetApiV1OrganizationsOrganizationIDRegionsRegionIDImagesWithResponse(ctx, g.organizationID, request.Spec.RegionId)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode() != http.StatusOK {
		return nil, errors.OAuth2ServerError("failed to list images")
	}

	images := *resp.JSON200

	// TODO: is the image compatible with the flavor virtualization type???
	images = slices.DeleteFunc(images, func(image regionapi.Image) bool {
		return g.filterImage(image, m)
	})

	if len(images) == 0 {
		return nil, errors.OAuth2ServerError("unable to select an image")
	}

	// Select the most recent, the region servie guarantees temporal ordering.
	return &images[0], nil
}

func (g *generator) filterImage(image regionapi.Image, m *openapi.MachinePool) bool {
	// If the image ID is set, we use it to get the image.
	if m.Image.Id != nil {
		return *m.Image.Id != image.Metadata.Id
	}

	// Is it the right distro?
	if image.Spec.Os.Distro != m.Image.Selector.Distro {
		return true
	}

	// Is it the right variant?
	if m.Image.Selector.Variant != nil {
		if image.Spec.Os.Variant == nil {
			return true
		}

		if *m.Image.Selector.Variant != *image.Spec.Os.Variant {
			return true
		}
	}

	// Is it the right version?
	if m.Image.Selector.Version != image.Spec.Os.Version {
		return true
	}

	return false
}

// generateNetwork generates the network part of a cluster.
func (g *generator) generateNetwork() *unikornv1core.NetworkGeneric {
	// Grab some defaults (as these are in the right format already)
	// the override with anything coming in from the API, if set.
	nodeNetwork := g.options.NodeNetwork
	dnsNameservers := g.options.DNSNameservers

	network := &unikornv1core.NetworkGeneric{
		NodeNetwork:    unikornv1core.IPv4Prefix{IPNet: nodeNetwork},
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
		Replicas: m.Replicas,
		ImageID:  image.Metadata.Id,
		FlavorID: flavor.Metadata.Id,
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

		firewall, err := generateFirewallRules(pool.Machine.Firewall)
		if err != nil {
			return nil, err
		}

		allowedAddressPairs, err := g.generateAllowedAddressPairs(pool.Machine.AllowedAddressPairs)
		if err != nil {
			return nil, err
		}

		workloadPool := unikornv1.ComputeClusterWorkloadPoolSpec{
			Name:                pool.Name,
			MachineGeneric:      *machine,
			PublicIPAllocation:  g.generatePublicIPAllocation(pool),
			Firewall:            firewall,
			UserData:            g.generateUserData(pool.Machine.UserData),
			ImageSelector:       g.generateImageSelector(pool.Machine.Image),
			AllowedAddressPairs: allowedAddressPairs,
		}

		workloadPools.Pools = append(workloadPools.Pools, workloadPool)
	}

	return workloadPools, nil
}

// generateAllowedAddressPairs generates the allowed address pairs part of a workload pool.
func (g *generator) generateAllowedAddressPairs(in *openapi.AllowedAddressPairList) ([]unikornv1.ComputeWorkloadPoolAddressPair, error) {
	if in == nil {
		return nil, nil
	}

	out := make([]unikornv1.ComputeWorkloadPoolAddressPair, len(*in))

	for i, ap := range *in {
		out[i] = unikornv1.ComputeWorkloadPoolAddressPair{}

		_, cidr, err := net.ParseCIDR(ap.Cidr)
		if err != nil {
			return nil, err
		}

		out[i].CIDR = unikornv1core.IPv4Prefix{
			IPNet: *cidr,
		}

		if ap.MacAddress != nil {
			out[i].MACAddress = *ap.MacAddress
		}
	}

	return out, nil
}

// generateImageSelector generates the image selector part of a workload pool.
func (g *generator) generateImageSelector(in openapi.ComputeImage) *unikornv1.ComputeWorkloadPoolImageSelector {
	if in.Id != nil {
		return nil
	}

	return &unikornv1.ComputeWorkloadPoolImageSelector{
		Distro:  unikornv1.OsDistro(in.Selector.Distro),
		Variant: in.Selector.Variant,
		Version: in.Selector.Version,
	}
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

func generateFirewallRuleDirection(in openapi.FirewallRuleDirection) unikornv1.FirewallRuleDirection {
	switch in {
	case openapi.Ingress:
		return unikornv1.Ingress
	case openapi.Egress:
		return unikornv1.Egress
	}

	return ""
}

func generateFirewallRuleProtocol(in openapi.FirewallRuleProtocol) unikornv1.FirewallRuleProtocol {
	switch in {
	case openapi.Tcp:
		return unikornv1.TCP
	case openapi.Udp:
		return unikornv1.UDP
	}

	return ""
}

func generatePrefixes(in []string) ([]unikornv1core.IPv4Prefix, error) {
	out := make([]unikornv1core.IPv4Prefix, len(in))

	for i := range in {
		_, cidr, err := net.ParseCIDR(in[i])
		if err != nil {
			return nil, err
		}

		out[i] = unikornv1core.IPv4Prefix{
			IPNet: *cidr,
		}
	}

	return out, nil
}

func generateFirewallRule(in *openapi.FirewallRule) (*unikornv1.FirewallRule, error) {
	prefixes, err := generatePrefixes(in.Prefixes)
	if err != nil {
		return nil, err
	}

	out := &unikornv1.FirewallRule{
		Direction: generateFirewallRuleDirection(in.Direction),
		Protocol:  generateFirewallRuleProtocol(in.Protocol),
		Port:      in.Port,
		PortMax:   in.PortMax,
		Prefixes:  prefixes,
	}

	return out, nil
}

func generateFirewallRules(in *openapi.FirewallRules) ([]unikornv1.FirewallRule, error) {
	if in == nil || len(*in) == 0 {
		return nil, nil
	}

	out := make([]unikornv1.FirewallRule, len(*in))

	for i := range *in {
		rule, err := generateFirewallRule(&(*in)[i])
		if err != nil {
			return nil, err
		}

		out[i] = *rule
	}

	return out, nil
}

// lookupFlavor resolves the flavor from its name.
// NOTE: It looks like garbage performance, but the provider should be memoized...
func (g *generator) lookupFlavor(ctx context.Context, request *openapi.ComputeClusterWrite, id string) (*regionapi.Flavor, error) {
	client, err := g.region.Client(ctx)
	if err != nil {
		return nil, err
	}

	resp, err := client.GetApiV1OrganizationsOrganizationIDRegionsRegionIDFlavorsWithResponse(ctx, g.organizationID, request.Spec.RegionId)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode() != http.StatusOK {
		return nil, coreapiutils.ExtractError(resp.StatusCode(), resp)
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

	out := &unikornv1.ComputeCluster{
		ObjectMeta: conversion.NewObjectMetadata(&request.Metadata, g.namespace).WithOrganization(g.organizationID).WithProject(g.projectID).Get(),
		Spec: unikornv1.ComputeClusterSpec{
			Tags:          conversion.GenerateTagList(request.Metadata.Tags),
			RegionID:      request.Spec.RegionId,
			Network:       g.generateNetwork(),
			WorkloadPools: computeWorkloadPools,
		},
	}

	if err := common.SetIdentityMetadata(ctx, &out.ObjectMeta); err != nil {
		return nil, errors.OAuth2ServerError("failed to set identity metadata").WithError(err)
	}

	return out, nil
}
