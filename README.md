# Unikorn Compute Service

![Unikorn Logo](https://raw.githubusercontent.com/unikorn-cloud/assets/main/images/logos/light-on-dark/logo.svg#gh-dark-mode-only)
![Unikorn Logo](https://raw.githubusercontent.com/unikorn-cloud/assets/main/images/logos/dark-on-light/logo.svg#gh-light-mode-only)

## Overview

The compute service is essentially a cut down version of the [Kubernetes service](https://github.com/unikorn-cloud/kubernetes) that provisions its own compute servers using hardware abstraction provided by the [Region service](https://github.com/unikorn-cloud/region).

Where possible, as the Compute service is very similar to the Kubernetes service, we must maintain type and API parity to ease creation of UX tools and services.

## Installation

### Unikorn Prerequisites

To use the Compute service you first need to install:

* [The identity service](https://github.com/unikorn-cloud/identity) to provide API authentication and authorization.
* [The region service](https://github.com/unikorn-cloud/region) to provide provider agnostic cloud services (e.g. images, flavors and identity management).

### Installing the Service

#### Installing Prerequisites

The Unikorn compute server component has a couple prerequisites that are required for correct functionality.
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
helm install unikorn-compute charts/compute --namespace unikorn-compute --create-namespace --values values.yaml
```

</details>

<details>
<summary>ArgoCD</summary>

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: unikorn-compute
  namespace: argocd
spec:
  project: default
  source:
    repoURL: https://unikorn-cloud.github.io/compute
    chart: compute
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
