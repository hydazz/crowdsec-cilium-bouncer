# CrowdSec Cilium Bouncer

This project provides a lightweight container that keeps Cilium in sync with CrowdSec decisions. It authenticates against the CrowdSec Local API using a bouncer API key, renders a deterministic `CiliumClusterwideNetworkPolicy`, and updates the policy on a configurable interval.

## Configuration

The bouncer is configured via environment variables:

- `CROWDSEC_URL` (required): Address of the CrowdSec Local API, e.g. `http://crowdsec-service.crowdsec-system.svc.cluster.local:8080`.
- `CROWDSEC_BOUNCER_API_KEY` (required): API key for the CrowdSec bouncer.
- `CROWDSEC_TIMEOUT`: HTTP timeout when talking to CrowdSec (default `1m`).
- `CROWDSEC_INSECURE_SKIP_VERIFY`: Set to `true` to skip TLS verification when using HTTPS.
- `CROWDSEC_FILTER_SCOPES`: Comma separated scopes to include (e.g. `Ip,Range`).
- `CROWDSEC_FILTER_TYPES`: Comma separated decision types to include (e.g. `ban`).
- `SYNC_INTERVAL`: How frequently to refresh decisions (default `30s`).
- `CILIUM_POLICY_NAME`: Name of the managed `CiliumClusterwideNetworkPolicy` (default `crowdsec-cilium-bouncer`).
- `CILIUM_POLICY_LABELS`: Additional labels to add to the policy, formatted as `key=value` pairs separated by commas.
- `CILIUM_ENDPOINT_SELECTOR`: Optional endpoint selector labels formatted as `key=value` pairs.
- `CILIUM_DENY_INGRESS`: Set to `false` to skip ingress deny rules (default `true`).
- `ALLOW_LOCAL_CIDRS`: Set to `true` to allow private/link-local addresses into the `CiliumClusterwideNetworkPolicy` (default `false`).
- `LOG_LEVEL`: Adjust log verbosity (`debug`, `info`, `warn`, `error`; default `info`).

## Running

The container is designed to run inside Kubernetes and relies on the in-cluster configuration to access the API server. Grant the pod a service account that can manage `CiliumClusterwideNetworkPolicies`. An example is available in `examples/install.yaml`:

```bash
kubectl apply -f examples/install.yaml
```

Update the namespace, image reference, and CrowdSec service URL to match your environment.

## Development

```bash
make tidy   # sync dependencies
make fmt    # format Go code
make test   # run unit tests
```

## License

GNU Affero General Public License v3.0
