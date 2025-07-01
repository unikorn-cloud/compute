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

//nolint:revive
package handler

import (
	"context"
	"net/http"
	"slices"

	"github.com/unikorn-cloud/compute/pkg/openapi"
	"github.com/unikorn-cloud/compute/pkg/server/handler/cluster"
	"github.com/unikorn-cloud/compute/pkg/server/handler/identity"
	"github.com/unikorn-cloud/compute/pkg/server/handler/region"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/core/pkg/server/util"
	identityclient "github.com/unikorn-cloud/identity/pkg/client"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"
	regionclient "github.com/unikorn-cloud/region/pkg/client"
	regionapi "github.com/unikorn-cloud/region/pkg/openapi"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

func regionClientGetter(issuer *identityclient.TokenIssuer, factory *regionclient.Client) region.ClientGetterFunc {
	return func(ctx context.Context) (regionapi.ClientWithResponsesInterface, error) {
		token, err := issuer.Issue(ctx, "kubernetes-api")
		if err != nil {
			return nil, err
		}

		client, err := factory.APIClient(ctx, token)
		if err != nil {
			return nil, err
		}

		return client, nil
	}
}

func identityClientGetter(issuer *identityclient.TokenIssuer, factory *identityclient.Client) identity.ClientGetterFunc {
	return func(ctx context.Context) (identityapi.ClientWithResponsesInterface, error) {
		token, err := issuer.Issue(ctx, "kubernetes-api")
		if err != nil {
			return nil, err
		}

		client, err := factory.APIClient(ctx, token)
		if err != nil {
			return nil, err
		}

		return client, nil
	}
}

type Handler struct {
	// client gives cached access to Compute.
	client client.Client

	// namespace is where the controller is running.
	namespace string

	// options allows behaviour to be defined on the CLI.
	options *Options

	// issuer provides privilge escallation for the API so the end user doesn't
	// have to be granted unnecessary privilige.
	issuer *identityclient.TokenIssuer

	// identity is a client to access the identity service.
	identity *identity.Client

	// region is a client to access regions.
	region *region.Client
}

func New(client client.Client, namespace string, options *Options, issuer *identityclient.TokenIssuer, identityFactory *identityclient.Client, regionFactory *regionclient.Client) (*Handler, error) {
	h := &Handler{
		client:    client,
		namespace: namespace,
		options:   options,
		issuer:    issuer,
		identity:  identity.New(identityClientGetter(issuer, identityFactory)),
		region:    region.New(regionClientGetter(issuer, regionFactory)),
	}

	return h, nil
}

/*
func (h *Handler) setCacheable(w http.ResponseWriter) {
	w.Header().Add("Cache-Control", fmt.Sprintf("max-age=%d", h.options.CacheMaxAge/time.Second))
	w.Header().Add("Cache-Control", "private")
}
*/

func (h *Handler) setUncacheable(w http.ResponseWriter) {
	w.Header().Add("Cache-Control", "no-cache")
}

func (h *Handler) GetApiV1OrganizationsOrganizationIDRegions(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter) {
	ctx := r.Context()

	if err := rbac.AllowOrganizationScope(ctx, "compute:regions", identityapi.Read, organizationID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := h.region.List(ctx, organizationID)
	if err != nil {
		errors.HandleError(w, r, errors.OAuth2ServerError("unable to read regions").WithError(err))
		return
	}

	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) GetApiV1OrganizationsOrganizationIDRegionsRegionIDFlavors(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, regionID openapi.RegionIDParameter) {
	ctx := r.Context()

	if err := rbac.AllowOrganizationScope(ctx, "compute:flavors", identityapi.Read, organizationID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := h.region.Flavors(ctx, organizationID, regionID)
	if err != nil {
		errors.HandleError(w, r, errors.OAuth2ServerError("unable to read flavors").WithError(err))
		return
	}

	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) GetApiV1OrganizationsOrganizationIDRegionsRegionIDImages(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, regionID openapi.RegionIDParameter) {
	ctx := r.Context()

	if err := rbac.AllowOrganizationScope(ctx, "compute:images", identityapi.Read, organizationID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := h.region.Images(ctx, organizationID, regionID)
	if err != nil {
		errors.HandleError(w, r, errors.OAuth2ServerError("unable to read flavors").WithError(err))
		return
	}

	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) clusterClient() *cluster.Client {
	return cluster.NewClient(h.client, h.namespace, &h.options.Cluster, h.identity, h.region)
}

func (h *Handler) GetApiV1OrganizationsOrganizationIDClusters(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, params openapi.GetApiV1OrganizationsOrganizationIDClustersParams) {
	ctx := r.Context()

	result, err := h.clusterClient().List(ctx, organizationID, params)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result = slices.DeleteFunc(result, func(resource openapi.ComputeClusterRead) bool {
		return rbac.AllowProjectScope(ctx, "compute:clusters", identityapi.Read, organizationID, resource.Metadata.ProjectId) != nil
	})

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) PostApiV1OrganizationsOrganizationIDProjectsProjectIDClusters(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter) {
	ctx := r.Context()

	if err := rbac.AllowProjectScope(ctx, "compute:clusters", identityapi.Create, organizationID, projectID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	request := &openapi.ComputeClusterWrite{}

	if err := util.ReadJSONBody(r, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := h.clusterClient().Create(ctx, organizationID, projectID, request)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusAccepted, result)
}

func (h *Handler) DeleteApiV1OrganizationsOrganizationIDProjectsProjectIDClustersClusterID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter, clusterID openapi.ClusterIDParameter) {
	ctx := r.Context()

	if err := rbac.AllowProjectScope(ctx, "compute:clusters", identityapi.Delete, organizationID, projectID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	if err := h.clusterClient().Delete(ctx, organizationID, projectID, clusterID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	w.WriteHeader(http.StatusAccepted)
}

func (h *Handler) PutApiV1OrganizationsOrganizationIDProjectsProjectIDClustersClusterID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter, clusterID openapi.ClusterIDParameter) {
	ctx := r.Context()

	if err := rbac.AllowProjectScope(ctx, "compute:clusters", identityapi.Update, organizationID, projectID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	request := &openapi.ComputeClusterWrite{}

	if err := util.ReadJSONBody(r, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	if err := h.clusterClient().Update(ctx, organizationID, projectID, clusterID, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	w.WriteHeader(http.StatusAccepted)
}
