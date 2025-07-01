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

package monitor

import (
	"context"
	"time"

	"github.com/spf13/pflag"

	clusterhealth "github.com/unikorn-cloud/compute/pkg/monitor/health/cluster"
	coreclient "github.com/unikorn-cloud/core/pkg/client"
	identityclient "github.com/unikorn-cloud/identity/pkg/client"
	"github.com/unikorn-cloud/identity/pkg/principal"
	regionclient "github.com/unikorn-cloud/region/pkg/client"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// Options allow modification of parameters via the CLI.
type Options struct {
	// pollPeriod defines how often to run.  There's no harm in having it
	// run with high frequency, reads are all cached.  It's mostly down to
	// burning CPU unnecessarily.
	pollPeriod time.Duration
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

// AddFlags registers option flags with pflag.
func (o *Options) AddFlags(f *pflag.FlagSet) {
	o.identityOptions = identityclient.NewOptions()
	o.regionOptions = regionclient.NewOptions()

	o.identityOptions.AddFlags(f)
	o.regionOptions.AddFlags(f)
	o.clientOptions.AddFlags(f)

	f.DurationVar(&o.pollPeriod, "poll-period", time.Minute, "Period to poll for updates")
}

// Checker is an interface that monitors must implement.
type Checker interface {
	// Check does whatever the checker is checking for.
	Check(ctx context.Context) error
}

// Run sits in an infinite loop, polling every so often.
func Run(ctx context.Context, c client.Client, o *Options) {
	ctx = principal.NewContext(ctx, &principal.Principal{Actor: "compute-monitor"})

	log := log.FromContext(ctx)

	ticker := time.NewTicker(o.pollPeriod)
	defer ticker.Stop()

	checkers := []Checker{
		clusterhealth.New(c, o.identityOptions, o.regionOptions, &o.clientOptions),
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for _, checker := range checkers {
				if err := checker.Check(ctx); err != nil {
					log.Error(err, "check failed")
				}
			}
		}
	}
}
