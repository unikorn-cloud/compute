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
	"slices"

	unikornv1 "github.com/unikorn-cloud/compute/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/compute/pkg/provisioners/managers/cluster/util"
	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	coreapi "github.com/unikorn-cloud/core/pkg/openapi"
)

// tags creates a set of tags to apply to servers and security groups etc. to help identify
// their owning clusters and pools.
func (p *Provisioner) tags(pool *unikornv1.ComputeClusterWorkloadPoolSpec) *coreapi.TagList {
	out := coreapi.TagList{
		{Name: coreconstants.ComputeClusterLabel, Value: p.cluster.Name},
		{Name: util.WorkloadPoolLabel, Value: pool.Name},
	}

	// Propagate any additional tags from the cluster's spec, if present
	for _, tag := range p.cluster.Spec.Tags {
		hasTag := func(t coreapi.Tag) bool {
			return t.Name == tag.Name
		}

		// Only add the tag if it doesn't already exist, so we prevent overwriting the default tags
		if !slices.ContainsFunc(out, hasTag) {
			out = append(out, coreapi.Tag{
				Name:  tag.Name,
				Value: tag.Value,
			})
		}
	}

	return &out
}
