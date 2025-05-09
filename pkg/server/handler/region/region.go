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
	"time"

	coreapiutils "github.com/unikorn-cloud/core/pkg/util/api"
	"github.com/unikorn-cloud/core/pkg/util/cache"
	regionapi "github.com/unikorn-cloud/region/pkg/openapi"
)

const (
	defaultCacheSize = 4096
)

// ClientGetterFunc allows us to lazily instantiate a client only when needed to
// avoid the TLS handshake and token exchange.
type ClientGetterFunc func(context.Context) (regionapi.ClientWithResponsesInterface, error)

// Client provides a caching layer for retrieval of region assets, and lazy population.
type Client struct {
	clientGetter  ClientGetterFunc
	client        regionapi.ClientWithResponsesInterface
	clientTimeout time.Time
	regionCache   *cache.LRUExpireCache[string, []regionapi.RegionRead]
	flavorCache   *cache.LRUExpireCache[string, []regionapi.Flavor]
	imageCache    *cache.LRUExpireCache[string, []regionapi.Image]
}

// New returns a new client.
func New(clientGetter ClientGetterFunc) *Client {
	return &Client{
		clientGetter: clientGetter,
		regionCache:  cache.NewLRUExpireCache[string, []regionapi.RegionRead](defaultCacheSize),
		flavorCache:  cache.NewLRUExpireCache[string, []regionapi.Flavor](defaultCacheSize),
		imageCache:   cache.NewLRUExpireCache[string, []regionapi.Image](defaultCacheSize),
	}
}

// Client returns a client.
func (c *Client) Client(ctx context.Context) (regionapi.ClientWithResponsesInterface, error) {
	if time.Now().Before(c.clientTimeout) {
		return c.client, nil
	}

	client, err := c.clientGetter(ctx)
	if err != nil {
		return nil, err
	}

	// TODO: the timeout should be driven by the token expiry, so we need to expose
	// that eventually.
	c.client = client
	c.clientTimeout = time.Now().Add(10 * time.Minute)

	return client, nil
}

// List lists all regions.
func (c *Client) List(ctx context.Context, organizationID string) ([]regionapi.RegionRead, error) {
	if regions, ok := c.regionCache.Get(organizationID); ok {
		return regions, nil
	}

	client, err := c.Client(ctx)
	if err != nil {
		return nil, err
	}

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

	c.regionCache.Add(organizationID, filtered, time.Hour)

	return filtered, nil
}

// Flavors returns all compute compatible flavors.
func (c *Client) Flavors(ctx context.Context, organizationID, regionID string) ([]regionapi.Flavor, error) {
	cacheKey := organizationID + ":" + regionID

	if flavors, ok := c.flavorCache.Get(cacheKey); ok {
		return flavors, nil
	}

	client, err := c.Client(ctx)
	if err != nil {
		return nil, err
	}

	resp, err := client.GetApiV1OrganizationsOrganizationIDRegionsRegionIDFlavorsWithResponse(ctx, organizationID, regionID)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode() != http.StatusOK {
		return nil, coreapiutils.ExtractError(resp.StatusCode(), resp)
	}

	flavors := *resp.JSON200

	c.flavorCache.Add(cacheKey, flavors, time.Hour)

	// TODO: filtering.
	return flavors, nil
}

// Images returns all compute compatible images.
func (c *Client) Images(ctx context.Context, organizationID, regionID string) ([]regionapi.Image, error) {
	cacheKey := organizationID + ":" + regionID

	if images, ok := c.imageCache.Get(cacheKey); ok {
		return images, nil
	}

	client, err := c.Client(ctx)
	if err != nil {
		return nil, err
	}

	resp, err := client.GetApiV1OrganizationsOrganizationIDRegionsRegionIDImagesWithResponse(ctx, organizationID, regionID)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode() != http.StatusOK {
		return nil, coreapiutils.ExtractError(resp.StatusCode(), resp)
	}

	images := *resp.JSON200

	c.imageCache.Add(cacheKey, images, time.Hour)

	// TODO: filtering.
	return images, nil
}
