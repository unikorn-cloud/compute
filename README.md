# Unikorn Baremetal Service

![Unikorn Logo](https://raw.githubusercontent.com/unikorn-cloud/assets/main/images/logos/light-on-dark/logo.svg#gh-dark-mode-only)
![Unikorn Logo](https://raw.githubusercontent.com/unikorn-cloud/assets/main/images/logos/dark-on-light/logo.svg#gh-light-mode-only)

## Overview

The baremetal service is essentially a cut down version of the [Kubernetes service](https://github.com/unikorn-cloud/kubernetes) that provisions its own baremetal servers using hardware abstraction prvoided by the [Region service](https://github.com/unikorn-cloud/region).

Where possible, as the Baremetal service is very similar to the Kubernetes service, we must maintain type and API parity ot ease creation of UX tools and services.

## Installation

### Unikorn Prerequisites

The use the Baremetal service you first need to install:

* [The identity service](https://github.com/unikorn-cloud/identity) to provide API authentication and authorization.
* [The region service](https://github.com/unikorn-cloud/region) to provide provider agnostic cloud services (e.g. images, flavors and identity management).

### Installing the Service

#### Installing Prerequisites

The Unikorn baremetal server component has a couple prerequisites that are required for correct functionality.
If not installing server you can skip to the next section.

You'll need to install:

* cert-manager (used to generate keying material for JWE/JWS and for ingress TLS)
* nginx-ingress (to perform routing, avoiding CORS, and TLS termination)

#### Installing the Baremetal Service

<details>
<summary>Helm</summary>

Create a `values.yaml` for the server component:
A typical `values.yaml` that uses cert-manager and ACME, and external DNS could look like:

```yaml
global:
  identity:
    host: https://identity.unikorn-cloud.org
  region:
    host: https://region.unikorn-cloud.org
  baremetal:
    host: https://baremetal.unikorn-cloud.org
```

```shell
helm install unikorn charts/unikorn --namespace unikorn --create-namespace --values values.yaml
```
</details>

<details>
<summary>ArgoCD</summary>

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: unikorn
  namespace: argocd
spec:
  project: default
  source:
    repoURL: https://unikorn-cloud.github.io/unikorn
    chart: unikorn
    targetRevision: v0.1.0
  destination:
    namespace: unikorn
    server: https://kubernetes.default.svc
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
    syncOptions:
    - CreateNamespace=true
```
</details>

### Configuring Service Authentication and Authorization

The [Unikorn Identity Service](https://github.com/unikorn-cloud/identity) describes how to configure a service organization, groups and role mappings for services that require them.

This service requires asynchronous access to the Unikorn Region API in order to poll cloud identity and physical network status during cluster creation, and delete those resources on cluster deletion.

This service defines the `unikorn-baremetal` user that will need to be added to a group in the service organization.
It will need the built in role `infra-manager-service` that allows:

* Read access to the `region` endpoints to access external networks
* Read/delete access to the `identites` endpoints to poll and delete cloud identities
* Read/delete access to the `physicalnetworks` endpoints to poll and delete physical networks
* Create/Read/Delete access to the `servers` endpoints to manage baremetal instances
