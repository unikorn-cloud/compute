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

package region

import (
	"context"
	"net/http"
	"slices"

	coreapiutils "github.com/unikorn-cloud/core/pkg/util/api"
	regionapi "github.com/unikorn-cloud/region/pkg/openapi"
)

// Regions lists all regions.
func Regions(ctx context.Context, client regionapi.ClientWithResponsesInterface, organizationID string) ([]regionapi.RegionRead, error) {
	resp, err := client.GetApiV1OrganizationsOrganizationIDRegionsWithResponse(ctx, organizationID)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode() != http.StatusOK {
		return nil, coreapiutils.ExtractError(resp.StatusCode(), resp)
	}

	regions := *resp.JSON200

	filter := func(x regionapi.RegionRead) bool {
		return x.Spec.Type == regionapi.Kubernetes
	}

	filtered, err := slices.DeleteFunc(regions, filter), nil
	if err != nil {
		return nil, err
	}

	return filtered, nil
}

// Flavors returns all Kubernetes compatible flavors.
func Flavors(ctx context.Context, client regionapi.ClientWithResponsesInterface, organizationID, regionID string) ([]regionapi.Flavor, error) {
	resp, err := client.GetApiV1OrganizationsOrganizationIDRegionsRegionIDFlavorsWithResponse(ctx, organizationID, regionID)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode() != http.StatusOK {
		return nil, coreapiutils.ExtractError(resp.StatusCode(), resp)
	}

	flavors := *resp.JSON200

	// TODO: filtering.
	return flavors, nil
}

// Images returns all Kubernetes compatible images.
func Images(ctx context.Context, client regionapi.ClientWithResponsesInterface, organizationID, regionID string) ([]regionapi.Image, error) {
	resp, err := client.GetApiV1OrganizationsOrganizationIDRegionsRegionIDImagesWithResponse(ctx, organizationID, regionID)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode() != http.StatusOK {
		return nil, coreapiutils.ExtractError(resp.StatusCode(), resp)
	}

	images := *resp.JSON200

	// TODO: filtering.
	return images, nil
}
