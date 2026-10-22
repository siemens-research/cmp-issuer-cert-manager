# CMP External Issuer for cert-manager

This repository contains an [external Issuer](https://cert-manager.io/docs/contributing/external-issuers/) for cert-manager that issues certificates using the **Certificate Management Protocol (CMP)**. It supports both a namespace-scoped `CMPIssuer` and a cluster-scoped `CMPClusterIssuer`, and is based on the [sample-external-issuer](https://github.com/cert-manager/sample-external-issuer) project.

> **Note:** This is a Proof of Concept (PoC). It is not intended for production use.

---

## Table of Contents

- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [1. Start Local EJBCA](#1-start-local-ejbca)
  - [2. Deploy the CMP Issuer Controller](#2-deploy-the-cmp-issuer-controller)
  - [3. Verify the Controller is Running](#3-verify-the-controller-is-running)
- [Configuring the Issuer](#configuring-the-issuer)
  - [Create the Authentication Secret](#create-the-authentication-secret)
  - [Create the CMPIssuer](#create-the-cmpissuer)
- [Requesting a Certificate](#requesting-a-certificate)
  - [Apply the Certificate Resource](#apply-the-certificate-resource)
  - [Verify the Certificate](#verify-the-certificate)
- [IssuerSpec Reference](#issuerspec-reference)
- [Secret Reference](#secret-reference)

---

## Getting Started

### Prerequisites

The following tools must be installed and available on your `PATH`:

| Tool | Purpose |
|---|---|
| [Docker](https://docs.docker.com/get-docker/) + [docker-compose](https://docs.docker.com/compose/install/) | Run local EJBCA and MariaDB |
| [Kind](https://kind.sigs.k8s.io/docs/user/quick-start/) | Local Kubernetes cluster |
| [kubectl](https://kubernetes.io/docs/tasks/tools/) | Interact with the cluster |
| [Go 1.21+](https://go.dev/dl/) | Build the controller |
| [make](https://www.gnu.org/software/make/) | Build automation |

cert-manager will be installed automatically as part of the deployment steps below.

---

### 1. Start Local EJBCA

The demo uses **EJBCA Community Edition 8.0.0** with **MariaDB 11.5.2**, managed via docker-compose.

Start both services:

```sh
make ejbca_start
```

This extracts the EJBCA docker-compose archive and starts the containers. EJBCA is exposed on:

- HTTP: `http://localhost:6080/ejbca`
- HTTPS: `https://localhost:6443/ejbca`

Wait until the EJBCA admin UI is accessible at `http://localhost:6080/ejbca/adminweb` before proceeding.

To stop EJBCA later:

```sh
make ejbca_stop
```

To restart:

```sh
make ejbca_restart
```

---

### 2. Deploy the CMP Issuer Controller

Create a fresh Kind cluster, build and load the controller image, install cert-manager, and deploy the CMP issuer:

```sh
kind delete cluster        # remove any existing Kind cluster
make docker-build          # build the controller container image
kind create cluster        # create a new Kind cluster
make deploy-cert-manager   # install cert-manager into the cluster
make kind-load             # load the controller image into Kind
make build-installer       # generate dist/install.yaml
kubectl apply -f dist/install.yaml
```

The controller is deployed into the `cmp-issuer-poc` namespace.

---

### 3. Verify the Controller is Running

Check that the controller pod is running:

```sh
kubectl get pods -n cmp-issuer-poc
```

Expected output:

```
NAME                                            READY   STATUS    RESTARTS   AGE
cmp-issuer-controller-manager-<hash>            1/1     Running   0          1m
```

Tail the controller logs:

```sh
export CMP_MANAGER_POD=$(kubectl get pods \
  -o go-template --template '{{range .items}}{{.metadata.name}}{{"\n"}}{{end}}' \
  -A | grep cmp-issuer-controller-manager)

kubectl logs $CMP_MANAGER_POD manager --follow -n cmp-issuer-poc -f
```

---

## Configuring the Issuer

cert-manager is configured for CMP using either a `CMPIssuer` (namespace-scoped) or a `CMPClusterIssuer` (cluster-wide). For the local EJBCA demo, a namespace-scoped `CMPIssuer` is used.

### Create the Authentication Secret

The CMP shared secret used to authenticate with EJBCA is stored in a Kubernetes Secret. Apply the pre-configured secret:

```sh
kubectl apply -f demo/localejbca/upstream-configuration_ejbca.yaml
```

The manifest content:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: upstream-conf-localejbca
data:
  # base64-encoded value of "SecretCmp"
  CmpSharedSecret: U2VjcmV0Q21w
```

> To encode your own shared secret: `echo -n "YourSecret" | base64`

---

### Create the CMPIssuer

Apply the `CMPIssuer` resource that points to the local EJBCA CMP endpoint:

```sh
kubectl apply -f demo/localejbca/ejbca-issuer_v1alpha1_cmpissuer.yaml
```

The manifest content:

```yaml
apiVersion: cmp-issuer.siemens.com/v1alpha1
kind: CMPIssuer
metadata:
  name: localejbca-cmpissuer
  labels:
    app.kubernetes.io/name: cmp-external-issuer
    app.kubernetes.io/managed-by: kustomize
spec:
  authSecretName: "upstream-conf-localejbca"
  url: "http://cmp-ejbca-issuer.siemens.com/api/v1"
  cmpserverurl: "http://10.0.2.15:6080/ejbca/publicweb/cmp/cmp_imprint_RA"
```

> **`url`** is the issuer service URL (used internally by the controller).  
> **`cmpserverurl`** is the actual CMP endpoint on the EJBCA server. Adjust the IP (`10.0.2.15`) to match your host's address as seen from the Kind cluster network.
>
> To find the correct IP, get the Docker bridge gateway address:
> ```sh
> docker network inspect bridge --format '{{(index .IPAM.Config 0).Gateway}}'
> ```
> This returns the address (e.g. `172.17.0.1`) that containers use to reach services running on your host machine.

Verify the issuer is ready:

```sh
kubectl get cmpissuer localejbca-cmpissuer
```

Expected output:

```
NAME                   READY   REASON    MESSAGE   LASTTRANSITION   OBSERVEDGENERATION   GENERATION   AGE
localejbca-cmpissuer   True    Checked             <timestamp>      1                    1            30s
```

---

## Requesting a Certificate

### Apply the Certificate Resource

Apply the cert-manager `Certificate` resource to request a certificate from the local EJBCA via CMP:

```sh
kubectl apply -f demo/localejbca/certificate_localejbca.yaml
```

The manifest content:

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: certificate-by-localejbca
spec:
  secretName: certificate-by-localejbca
  commonName: test-localejbca-cmpissuer.siemens.com
  subject:
    organizations:
      - "Siemens"
    countries:
      - "DE"
  issuerRef:
    name: localejbca-cmpissuer
    group: cmp-issuer.siemens.com
    kind: CMPIssuer
  privateKey:
    algorithm: RSA
    encoding: PKCS1
    size: 4096
  duration: 2160h   # 90 days
  renewBefore: 360h # 15 days
```

---

### Verify the Certificate

Check the certificate status:

```sh
kubectl get certificate certificate-by-localejbca
```

Expected output when successfully issued:

```
NAME                        READY   SECRET                      AGE
certificate-by-localejbca   True    certificate-by-localejbca   1m
```

Verify the TLS secret was created:

```sh
kubectl get secret certificate-by-localejbca
```

Expected output:

```
NAME                        TYPE                DATA   AGE
certificate-by-localejbca   kubernetes.io/tls   3      1m
```

Inspect the issued certificate:

```sh
kubectl get secret certificate-by-localejbca -o jsonpath='{.data.tls\.crt}' \
  | base64 -d | openssl x509 -noout -subject -issuer -dates
```

---

## IssuerSpec Reference

The following fields are available in the `spec` of a `CMPIssuer` or `CMPClusterIssuer`:

| Field | Type | Required | Description |
|---|---|---|---|
| `url` | string | Yes | Base URL for the issuer service endpoint (used internally by the controller). |
| `authSecretName` | string | Yes | Name of the Kubernetes Secret containing credentials. See [Secret Reference](#secret-reference). |
| `cmpserverurl` | string | Yes | Direct URL to the CMP server endpoint (e.g., the EJBCA CMP servlet path). |
| `cmpsignercert` | string | Required if `CmpSharedSecret` is not set | PEM-encoded certificate chain used to sign CMP requests (signature-based protection). |
| `cmpsignerkey` | string | Required if `CmpSharedSecret` is not set | PEM-encoded private key for signing CMP requests. May be passphrase-encrypted; provide passphrase via `CMPSignerPassphrase` in the Secret. |
| `cmptrusted` | string | No | PEM-encoded trusted certificate(s) used to verify the CMP server response. Optional in both MAC-based and signature-based protection modes. |
| `tlsclientcert` | string | No | PEM-encoded client certificate for mutual TLS (mTLS) to the CMP endpoint. If set, `tlsclientkey` and `tlstrusted` must also be set. |
| `tlsclientkey` | string | Required if `tlsclientcert` is set | PEM-encoded client private key for mTLS. May be passphrase-encrypted; provide passphrase via `TLSClientPassphrase` in the Secret. |
| `tlstrusted` | string | Required if `tlsclientcert` is set | PEM-encoded trusted certificates used to verify the CMP server's TLS certificate (for HTTPS endpoints). |

**Protection modes:** The issuer supports two CMP request protection modes, selected automatically based on the presence of `CmpSharedSecret` in the referenced Secret:
- **MAC-based (shared secret):** Used when `CmpSharedSecret` is set in the Secret. This is the mode used in the local EJBCA demo. `cmpsignercert`/`cmpsignerkey` are not required in this mode.
- **Signature-based:** Used when `CmpSharedSecret` is *not* set. In this case `cmpsignercert` and `cmpsignerkey` (or their passphrase-protected equivalents in the Secret) are mandatory.

**TLS transport (optional mTLS):** If `tlsclientcert` is provided, `tlsclientkey` and `tlstrusted` must also be provided. If `tlsclientcert` is omitted, the controller falls back to the default TLS configuration for the CMP HTTP(S) connection (no client certificate is presented).

**Note on differing enrollment and infrastructure PKIs:** If the CA that issues the enrolled certificate differs from the CA that protects the CMP message exchange itself, include the root CA certificate(s) from **both** PKIs in `cmptrusted`. 

**Runtime CMP client flags:** Internally, `CmpSigner.Sign` sets numbers of hardcoded protocol flags on the `CMPClient` (e.g. `acceptNewCertValidationFailure`, `preferCRMF`) — see `internal/signer/cmp_client.go` for the full `CMPClientFlags` struct and their meaning. These are not currently exposed via `IssuerSpec` and cannot be configured per-issuer.

---

## Secret Reference

The Secret referenced by `authSecretName` may contain the following keys:

| Key | Type | Description |
|---|---|---|
| `CmpSharedSecret` | string (base64) | Shared secret for MAC-based CMP request protection. Used in place of certificate-based signing. |
| `CMPSignerPassphrase` | string (base64) | Passphrase to decrypt an encrypted `cmpsignerkey` provided in the `IssuerSpec`. |
| `TLSClientPassphrase` | string (base64) | Passphrase to decrypt an encrypted `tlsclientkey` provided in the `IssuerSpec`. |
| `TLSTrusted` | string (base64) | Alternative location for the TLS trust anchor PEM. Takes precedence over `tlstrusted` in the spec if both are set. |

---

## License

This work is licensed under the terms of the Apache Software License 2.0.
See the [LICENSE.txt](LICENSE.txt) file in the top-level directory.

SPDX-License-Identifier: Apache-2.0