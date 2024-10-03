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

//nolint:revive,stylecheck
package handler

import (
	"net/http"
	"slices"

	"github.com/unikorn-cloud/baremetal/pkg/openapi"
	"github.com/unikorn-cloud/baremetal/pkg/server/handler/cluster"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/core/pkg/server/util"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"
	regionclient "github.com/unikorn-cloud/region/pkg/client"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Handler struct {
	// client gives cached access to Baremetal.
	client client.Client

	// namespace is where the controller is running.
	namespace string

	// options allows behaviour to be defined on the CLI.
	options *Options

	// region is a client to access regions.
	region *regionclient.Client
}

func New(client client.Client, namespace string, options *Options, region *regionclient.Client) (*Handler, error) {
	h := &Handler{
		client:    client,
		namespace: namespace,
		options:   options,
		region:    region,
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

func (h *Handler) GetApiV1OrganizationsOrganizationIDClusters(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter) {
	region, err := h.region.Client(r.Context())
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := cluster.NewClient(h.client, h.namespace, &h.options.Cluster, region).List(r.Context(), organizationID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result = slices.DeleteFunc(result, func(resource openapi.BaremetalClusterRead) bool {
		return rbac.AllowProjectScope(r.Context(), "baremetalclusters", identityapi.Read, organizationID, resource.Metadata.ProjectId) != nil
	})

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) PostApiV1OrganizationsOrganizationIDProjectsProjectIDClusters(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter) {
	if err := rbac.AllowProjectScope(r.Context(), "baremetalclusters", identityapi.Create, organizationID, projectID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	request := &openapi.BaremetalClusterWrite{}

	if err := util.ReadJSONBody(r, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	region, err := h.region.Client(r.Context())
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := cluster.NewClient(h.client, h.namespace, &h.options.Cluster, region).Create(r.Context(), organizationID, projectID, request)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusAccepted, result)
}

func (h *Handler) DeleteApiV1OrganizationsOrganizationIDProjectsProjectIDClustersClusterID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter, clusterID openapi.ClusterIDParameter) {
	if err := rbac.AllowProjectScope(r.Context(), "baremetalclusters", identityapi.Delete, organizationID, projectID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	region, err := h.region.Client(r.Context())
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	if err := cluster.NewClient(h.client, h.namespace, &h.options.Cluster, region).Delete(r.Context(), organizationID, projectID, clusterID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	w.WriteHeader(http.StatusAccepted)
}

func (h *Handler) PutApiV1OrganizationsOrganizationIDProjectsProjectIDClustersClusterID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter, clusterID openapi.ClusterIDParameter) {
	if err := rbac.AllowProjectScope(r.Context(), "baremetalclusters", identityapi.Update, organizationID, projectID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	request := &openapi.BaremetalClusterWrite{}

	if err := util.ReadJSONBody(r, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	region, err := h.region.Client(r.Context())
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	if err := cluster.NewClient(h.client, h.namespace, &h.options.Cluster, region).Update(r.Context(), organizationID, projectID, clusterID, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	w.WriteHeader(http.StatusAccepted)
}
