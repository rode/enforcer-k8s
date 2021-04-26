# enforcer-k8s

A Kubernetes [validating admission webhook](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#validatingadmissionwebhook)
that checks any container images in a pod against a specified policy.

It's intended to be used alongside [Rode](https://github.com/rode/rode) to prevent deployments that fail to meet certain checks.

## Local Development

This project requires Go 1.16 or newer.

1. Follow the instructions to run [Rode locally](https://github.com/rode/rode/blob/main/docs/development.md#development)
1. Run `skaffold dev`
    - Alternatively, if you have [Telepresence](https://www.telepresence.io/) installed, run the enforcer on the host:
    ```bash
    go run main.go --rode-host=rode.rode-demo.svc.cluster.local:50051 \
        --rode-insecure \
        --policy-id="$POLICY_ID" \
        --tls-secret=default/enforcer-k8s \
        --k8s-in-cluster=false \
        --debug \
        --registry-insecure-skip-verify=true
    ```
1. Make any changes, then use `make test` to run the unit tests
   - If necessary, use `make fmt` to address any formatting issues
1. If new files were added, use `make license` to add the required source code headers


## Installation

See the [`rode/charts`](https://github.com/rode/charts) repository to use the Helm chart.

### Flags

| Option                            | Description                                                         | Default              |
|-----------------------------------|---------------------------------------------------------------------|----------------------|
| `--debug`                         | Set the log level to debug                                          | `false`              |
| `--k8s-config-file`               | Path to the Kubernetes config file                                  | `$HOME/.kube/config` |
| `--k8s-in-cluster`                | Whether the enforcer should use the in-cluster Kubernetes config    | `true`               |
| `--policy-id`                     | The id of the policy to enforce                                     | N/A                  |
| `--port`                          | The port the HTTP server should bind against                        | `8001`               |
| `--registry-insecure-skip-verify` | Whether TLS should be verified when talking to container registries | `false`              |
| `--rode-host`                     | The hostname of the Rode instance                                   | N/A                  |
| `--rode-insecure`                 | Whether TLS should be verified when talking to Rode                 | `false`              |