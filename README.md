# UNI Compute Service

## Overview

The compute service is essentially a cut down version of the [Kubernetes service](https://github.com/nscaledev/uni-kubernetes) that provisions its own compute servers using hardware abstraction provided by the [Region service](https://github.com/nscaledev/uni-region).

Where possible, as the Compute service is very similar to the Kubernetes service, we must maintain type and API parity to ease creation of UX tools and services.

## Installation

### UNI Prerequisites

To use the Compute service you first need to install:

* [The identity service](https://github.com/nscaledev/uni-identity) to provide API authentication and authorization.
* [The region service](https://github.com/nscaledev/uni-region) to provide provider agnostic cloud services (e.g. images, flavors and identity management).

### Installing the Service

#### Installing Prerequisites

The UNI compute server component has a couple prerequisites that are required for correct functionality.
If not installing the server component, skip to the next section.

You'll need to install:

* cert-manager (used to generate keying material for JWE/JWS and for ingress TLS)
* nginx-ingress (to perform routing, avoiding CORS, and TLS termination)

#### Installing the Compute Service

<details>
<summary>Helm</summary>

Create a `values.yaml` for the server component:
A typical `values.yaml` that uses cert-manager and ACME, and external DNS might look like:

```yaml
global:
  identity:
    host: https://identity.unikorn-cloud.org
  region:
    host: https://region.unikorn-cloud.org
  compute:
    host: https://compute.unikorn-cloud.org
```

```shell
helm install uni-compute charts/compute --namespace uni-compute --create-namespace --values values.yaml
```

</details>

<details>
<summary>ArgoCD</summary>

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: uni-compute
  namespace: argocd
spec:
  project: default
  source:
    repoURL: https://nscaledev.github.io/compute
    chart: compute
    targetRevision: v0.1.0
  destination:
    namespace: uni-compute
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

The [UNI Identity Service](https://github.com/nscaledev/uni-identity) describes how to configure a service organization, groups and role mappings for services that require them.

This service requires asynchronous access to the UNI Region API in order to poll cloud identity and physical network status during cluster creation, and delete those resources on cluster deletion.

This service defines the `uni-compute` user that will need to be added to a group in the service organization.
It will need the built in role `infra-manager-service` that allows:

* Read access to the `region` endpoints to access external networks
* Read/delete access to the `identites` endpoints to poll and delete cloud identities
* Read/delete access to the `physicalnetworks` endpoints to poll and delete physical networks
* Create/Read/Delete access to the `servers` endpoints to manage compute instances
