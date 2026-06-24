#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

cluster_name="edgepacer-validation"
namespace="logpacer-system"
sample_namespace="edgepacer-validation"
release_name="edgepacer"
chart_dir="${repo_root}/charts/edgepacer"
rails_url="https://app.logpacer.com"
secret_name="edgepacer-auth"
account_token_key="account-token"
account_token_file=""
output_dir="${TMPDIR:-/tmp}/edgepacer-k8s-validation"
rollout_timeout="180s"
image_repository=""
image_tag=""
image_pull_secret=""
create_image_pull_secret=0
registry_server="ghcr.io"
registry_username_env="GHCR_USERNAME"
registry_password_env="GHCR_TOKEN"
extra_helm_args=()

allow_dummy_token=1
cleanup_only=0
create_cluster=1
delete_cluster_on_exit=0
dry_run=0
install_agent=1
render_only=0
require_agent_ready=0
use_existing_cluster=0
deploy_samples=1
cluster_created=0

cleanup_created_cluster_on_exit() {
  local status=$?
  trap - EXIT

  if [[ "${delete_cluster_on_exit}" -eq 1 && "${cluster_created}" -eq 1 ]]; then
    log "Deleting kind cluster created by this run: ${cluster_name}"
    if [[ "${dry_run}" -eq 0 ]]; then
      kind delete cluster --name "${cluster_name}" || log "warning: failed to delete kind cluster ${cluster_name}"
    else
      log "+ kind delete cluster --name ${cluster_name}"
    fi
  fi

  exit "${status}"
}

trap cleanup_created_cluster_on_exit EXIT

usage() {
  cat <<'USAGE'
Validate EdgePacer DaemonSet mode in a local kind cluster.

Usage:
  scripts/kubernetes/validate-kind.sh [options]

Default behavior:
  - lint and render charts/edgepacer
  - create or reuse kind cluster edgepacer-validation
  - create the EdgePacer account-token Secret from a token file or dummy local token
  - helm upgrade --install the DaemonSet chart
  - deploy one opted-in and one non-opted-in sample workload
  - print diagnostics

Options:
  --account-token-file PATH   Read the LogPacer account token from PATH. The token value is never accepted as a CLI flag.
  --chart-dir PATH            Helm chart path. Default: charts/edgepacer
  --cleanup                   Delete the validation kind cluster, or uninstall resources from the current cluster with --use-existing-cluster.
  --cluster-name NAME         kind cluster name. Default: edgepacer-validation
  --delete-cluster-on-exit    Delete a kind cluster created by this run after diagnostics complete.
  --dry-run                   Print commands without changing the cluster.
  --image-repository REPO     Override image.repository for the Helm install.
  --image-tag TAG             Override image.tag for the Helm install.
  --image-pull-secret NAME    Set Helm imagePullSecrets[0].name.
  --namespace NAME            EdgePacer namespace. Default: logpacer-system
  --no-dummy-token            Require --account-token-file instead of creating a local dummy token.
  --no-input                  Accepted for CI callers. The script never prompts.
  --output-dir PATH           Directory for rendered YAML and generated sample manifests.
  --rails-url URL             EDGEPACER_RAILS_URL value. Default: https://app.logpacer.com
  --release NAME              Helm release name. Default: edgepacer
  --render-only               Only run helm lint/template. Do not touch a cluster.
  --require-agent-ready       Wait for the EdgePacer DaemonSet rollout and fail if the image/token/backend are not usable.
  --rollout-timeout DURATION  Timeout for rollout and workload waits. Default: 180s
  --sample-namespace NAME     Sample workload namespace. Default: edgepacer-validation
  --secret-name NAME          Existing Secret name consumed by the chart. Default: edgepacer-auth
  --create-image-pull-secret  Create/update --image-pull-secret from registry env vars.
  --registry-server SERVER    Registry server for created pull secret. Default: ghcr.io
  --registry-username-env ENV Environment variable holding registry username. Default: GHCR_USERNAME
  --registry-password-env ENV Environment variable holding registry token/password. Default: GHCR_TOKEN
  --helm-set KEY=VALUE       Append a Helm --set override.
  --helm-set-string KEY=VALUE Append a Helm --set-string override.
  --skip-agent-install        Do not install the EdgePacer Helm release.
  --skip-samples              Do not deploy sample workloads.
  --use-existing-cluster      Use the active kubectl context instead of creating/switching to a kind cluster.
  -h, --help                  Show this help.

Examples:
  scripts/kubernetes/validate-kind.sh --render-only
  scripts/kubernetes/validate-kind.sh --delete-cluster-on-exit
  scripts/kubernetes/validate-kind.sh --account-token-file ./tmp/logpacer-token --require-agent-ready
USAGE
}

log() {
  printf '%s\n' "$*" >&2
}

die() {
  log "error: $*"
  exit 1
}

run() {
  log "+ $*"
  if [[ "${dry_run}" -eq 0 ]]; then
    "$@"
  fi
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

parse_args() {
  while [[ "$#" -gt 0 ]]; do
    case "$1" in
      --account-token-file)
        account_token_file="${2:?missing value for --account-token-file}"
        shift 2
        ;;
      --chart-dir)
        chart_dir="${2:?missing value for --chart-dir}"
        shift 2
        ;;
      --cleanup)
        cleanup_only=1
        shift
        ;;
      --cluster-name)
        cluster_name="${2:?missing value for --cluster-name}"
        shift 2
        ;;
      --delete-cluster-on-exit)
        delete_cluster_on_exit=1
        shift
        ;;
      --dry-run)
        dry_run=1
        shift
        ;;
      --image-repository)
        image_repository="${2:?missing value for --image-repository}"
        shift 2
        ;;
      --image-tag)
        image_tag="${2:?missing value for --image-tag}"
        shift 2
        ;;
      --image-pull-secret)
        image_pull_secret="${2:?missing value for --image-pull-secret}"
        shift 2
        ;;
      --namespace)
        namespace="${2:?missing value for --namespace}"
        shift 2
        ;;
      --no-dummy-token)
        allow_dummy_token=0
        shift
        ;;
      --no-input)
        shift
        ;;
      --output-dir)
        output_dir="${2:?missing value for --output-dir}"
        shift 2
        ;;
      --rails-url)
        rails_url="${2:?missing value for --rails-url}"
        shift 2
        ;;
      --release)
        release_name="${2:?missing value for --release}"
        shift 2
        ;;
      --render-only)
        render_only=1
        create_cluster=0
        install_agent=0
        deploy_samples=0
        shift
        ;;
      --require-agent-ready)
        require_agent_ready=1
        shift
        ;;
      --rollout-timeout)
        rollout_timeout="${2:?missing value for --rollout-timeout}"
        shift 2
        ;;
      --sample-namespace)
        sample_namespace="${2:?missing value for --sample-namespace}"
        shift 2
        ;;
      --secret-name)
        secret_name="${2:?missing value for --secret-name}"
        shift 2
        ;;
      --create-image-pull-secret)
        create_image_pull_secret=1
        shift
        ;;
      --registry-server)
        registry_server="${2:?missing value for --registry-server}"
        shift 2
        ;;
      --registry-username-env)
        registry_username_env="${2:?missing value for --registry-username-env}"
        shift 2
        ;;
      --registry-password-env)
        registry_password_env="${2:?missing value for --registry-password-env}"
        shift 2
        ;;
      --helm-set)
        extra_helm_args+=("--set" "${2:?missing value for --helm-set}")
        shift 2
        ;;
      --helm-set=*)
        extra_helm_args+=("--set" "${1#--helm-set=}")
        shift
        ;;
      --helm-set-string)
        extra_helm_args+=("--set-string" "${2:?missing value for --helm-set-string}")
        shift 2
        ;;
      --helm-set-string=*)
        extra_helm_args+=("--set-string" "${1#--helm-set-string=}")
        shift
        ;;
      --skip-agent-install)
        install_agent=0
        shift
        ;;
      --skip-samples)
        deploy_samples=0
        shift
        ;;
      --use-existing-cluster)
        use_existing_cluster=1
        create_cluster=0
        shift
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        die "unknown option: $1"
        ;;
    esac
  done
}

normalize_args() {
  if [[ "${create_image_pull_secret}" -eq 1 && -z "${image_pull_secret}" ]]; then
    image_pull_secret="ghcr-pull"
  fi
}

helm_common_args() {
  local args=(
    "--namespace" "${namespace}"
    "--set-string" "controlPlane.railsUrl=${rails_url}"
    "--set" "auth.createSecret=false"
    "--set-string" "auth.existingSecret=${secret_name}"
    "--set-string" "auth.accountTokenKey=${account_token_key}"
    "--set" "traces.otlpHttp.enabled=true"
    "--set" "traces.otlpHttp.listenerConfiguredByControlPlane=true"
    "--set" "traces.service.enabled=true"
    "--set-string" "traces.service.internalTrafficPolicy=Local"
    "--set" "traces.networkPolicy.enabled=true"
  )

  if [[ -n "${image_repository}" ]]; then
    args+=("--set-string" "image.repository=${image_repository}")
  fi

  if [[ -n "${image_tag}" ]]; then
    args+=("--set-string" "image.tag=${image_tag}")
  fi

  if [[ -n "${image_pull_secret}" ]]; then
    args+=("--set-string" "imagePullSecrets[0].name=${image_pull_secret}")
  fi

  if [[ "${#extra_helm_args[@]}" -gt 0 ]]; then
    args+=("${extra_helm_args[@]}")
  fi

  printf '%s\n' "${args[@]}"
}

json_escape() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  value="${value//$'\n'/\\n}"
  value="${value//$'\r'/\\r}"
  value="${value//$'\t'/\\t}"
  printf '%s\n' "${value}"
}

edgepacer_daemonset_selector() {
  printf 'app.kubernetes.io/instance=%s,app.kubernetes.io/component=agent\n' "${release_name}"
}

check_cleanup_prerequisites() {
  if [[ "${dry_run}" -eq 1 ]]; then
    return
  fi

  if [[ "${use_existing_cluster}" -eq 0 ]]; then
    require_cmd kind
  else
    require_cmd helm
    require_cmd kubectl
  fi
}

check_prerequisites() {
  require_cmd helm

  if [[ "${render_only}" -eq 1 || "${dry_run}" -eq 1 ]]; then
    return
  fi

  require_cmd kubectl

  if [[ "${use_existing_cluster}" -eq 0 ]]; then
    require_cmd kind
  fi

  if [[ "${create_cluster}" -eq 1 ]]; then
    require_cmd docker
    docker info >/dev/null 2>&1 || die "Docker is not available to kind"
  fi
}

render_chart() {
  log "Linting ${chart_dir}"
  run helm lint "${chart_dir}"

  local rendered_manifest="${output_dir}/edgepacer-rendered.yaml"
  local helm_args=()
  local arg
  while IFS= read -r arg; do
    helm_args+=("${arg}")
  done < <(helm_common_args)

  log "+ helm template ${release_name} ${chart_dir} ${helm_args[*]} > ${rendered_manifest}"
  if [[ "${dry_run}" -eq 0 ]]; then
    mkdir -p "${output_dir}"
    helm template "${release_name}" "${chart_dir}" "${helm_args[@]}" > "${rendered_manifest}"
    log "Rendered chart: ${rendered_manifest}"
  else
    log "Would render chart: ${rendered_manifest}"
  fi
}

kind_cluster_exists() {
  kind get clusters 2>/dev/null | grep -Fxq "${cluster_name}"
}

ensure_cluster() {
  if [[ "${use_existing_cluster}" -eq 1 ]]; then
    run kubectl cluster-info
    return
  fi

  if [[ "${dry_run}" -eq 1 ]]; then
    cluster_created=1
    run kind create cluster --name "${cluster_name}"
    run kubectl config use-context "kind-${cluster_name}"
    run kubectl wait --for=condition=Ready nodes --all --timeout="${rollout_timeout}"
    return
  fi

  if kind_cluster_exists; then
    log "Using existing kind cluster: ${cluster_name}"
  else
    cluster_created=1
    run kind create cluster --name "${cluster_name}"
  fi

  run kubectl config use-context "kind-${cluster_name}"
  run kubectl wait --for=condition=Ready nodes --all --timeout="${rollout_timeout}"
}

token_file_for_secret() {
  if [[ -n "${account_token_file}" ]]; then
    [[ -f "${account_token_file}" ]] || die "account token file does not exist: ${account_token_file}"
    printf '%s\n' "${account_token_file}"
    return
  fi

  [[ "${allow_dummy_token}" -eq 1 ]] || die "missing --account-token-file and --no-dummy-token was set"

  local dummy_file="${output_dir}/dummy-account-token"
  if [[ "${dry_run}" -eq 0 ]]; then
    mkdir -p "${output_dir}"
    printf '%s\n' "local-validation-token" > "${dummy_file}"
    chmod 0600 "${dummy_file}"
  fi

  log "Using a dummy local token. Add --account-token-file and --require-agent-ready for a real backend check."
  printf '%s\n' "${dummy_file}"
}

ensure_namespace() {
  local target_namespace="$1"

  if [[ "${dry_run}" -eq 1 ]]; then
    run kubectl create namespace "${target_namespace}"
    return
  fi

  if kubectl get namespace "${target_namespace}" >/dev/null 2>&1; then
    log "Namespace exists: ${target_namespace}"
  else
    run kubectl create namespace "${target_namespace}"
  fi
}

install_secret() {
  local token_file
  token_file="$(token_file_for_secret)"

  ensure_namespace "${namespace}"

  if [[ "${dry_run}" -eq 0 ]] && kubectl -n "${namespace}" get secret "${secret_name}" >/dev/null 2>&1; then
    run kubectl -n "${namespace}" delete secret "${secret_name}"
  fi

  run kubectl -n "${namespace}" create secret generic "${secret_name}" "--from-file=${account_token_key}=${token_file}"
}

install_image_pull_secret() {
  if [[ "${create_image_pull_secret}" -ne 1 ]]; then
    return 0
  fi

  ensure_namespace "${namespace}"

  if [[ "${dry_run}" -eq 1 ]]; then
    log "Would create image pull secret ${image_pull_secret} in ${namespace} from ${registry_username_env}/${registry_password_env}."
    return
  fi

  local username="${!registry_username_env:-}"
  local password="${!registry_password_env:-}"
  [[ -n "${username}" ]] || die "missing registry username env var: ${registry_username_env}"
  [[ -n "${password}" ]] || die "missing registry password env var: ${registry_password_env}"

  mkdir -p "${output_dir}"
  local docker_config
  docker_config="$(mktemp "${output_dir}/dockerconfig.XXXXXX")"
  trap 'rm -f "${docker_config}"' RETURN
  chmod 0600 "${docker_config}"

  local auth
  auth="$(printf '%s:%s' "${username}" "${password}" | base64 | tr -d '\n')"

  cat > "${docker_config}" <<JSON
{
  "auths": {
    "$(json_escape "${registry_server}")": {
      "username": "$(json_escape "${username}")",
      "password": "$(json_escape "${password}")",
      "auth": "${auth}"
    }
  }
}
JSON

  if kubectl -n "${namespace}" get secret "${image_pull_secret}" >/dev/null 2>&1; then
    run kubectl -n "${namespace}" delete secret "${image_pull_secret}"
  fi

  run kubectl -n "${namespace}" create secret generic "${image_pull_secret}" \
    --type=kubernetes.io/dockerconfigjson \
    "--from-file=.dockerconfigjson=${docker_config}"
  rm -f "${docker_config}"
  trap - RETURN
}

install_edgepacer() {
  install_secret
  install_image_pull_secret

  local helm_args=()
  local arg
  while IFS= read -r arg; do
    helm_args+=("${arg}")
  done < <(helm_common_args)

  local install_args=(
    upgrade
    --install
    "${release_name}"
    "${chart_dir}"
    "--create-namespace"
  )
  install_args+=("${helm_args[@]}")

  if [[ "${require_agent_ready}" -eq 1 ]]; then
    install_args+=("--wait" "--timeout" "${rollout_timeout}")
  fi

  run helm "${install_args[@]}"

  if [[ "${require_agent_ready}" -eq 1 ]]; then
    run kubectl -n "${namespace}" rollout status daemonset -l "$(edgepacer_daemonset_selector)" "--timeout=${rollout_timeout}"
  else
    log "EdgePacer rollout is not required in this mode. Use --require-agent-ready with a pullable image and real token to enforce it."
  fi
}

write_sample_manifest() {
  local sample_manifest="${output_dir}/sample-workloads.yaml"
  if [[ "${dry_run}" -eq 1 ]]; then
    log "Would write sample manifest: ${sample_manifest}"
    printf '%s\n' "${sample_manifest}"
    return
  fi

  mkdir -p "${output_dir}"

  cat > "${sample_manifest}" <<YAML
apiVersion: v1
kind: Namespace
metadata:
  name: ${sample_namespace}
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: edgepacer-opted-in
  namespace: ${sample_namespace}
  labels:
    app.kubernetes.io/name: edgepacer-opted-in
spec:
  replicas: 1
  selector:
    matchLabels:
      app.kubernetes.io/name: edgepacer-opted-in
  template:
    metadata:
      labels:
        app.kubernetes.io/name: edgepacer-opted-in
        logpacer.com/service-name: edgepacer-validation-opted-in
      annotations:
        logpacer.com/service-name: edgepacer-validation-opted-in
    spec:
      containers:
        - name: app
          image: busybox:1.36
          imagePullPolicy: IfNotPresent
          command:
            - /bin/sh
            - -c
          args:
            - |
              i=0
              while true; do
                echo "edgepacer opted-in log line \${i}"
                i=\$((i + 1))
                sleep 5
              done
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: edgepacer-not-opted-in
  namespace: ${sample_namespace}
  labels:
    app.kubernetes.io/name: edgepacer-not-opted-in
spec:
  replicas: 1
  selector:
    matchLabels:
      app.kubernetes.io/name: edgepacer-not-opted-in
  template:
    metadata:
      labels:
        app.kubernetes.io/name: edgepacer-not-opted-in
    spec:
      containers:
        - name: app
          image: busybox:1.36
          imagePullPolicy: IfNotPresent
          command:
            - /bin/sh
            - -c
          args:
            - |
              i=0
              while true; do
                echo "edgepacer not-opted-in log line \${i}"
                i=\$((i + 1))
                sleep 5
              done
YAML

  printf '%s\n' "${sample_manifest}"
}

deploy_sample_workloads() {
  local sample_manifest
  sample_manifest="$(write_sample_manifest)"

  run kubectl apply -f "${sample_manifest}"
  run kubectl -n "${sample_namespace}" rollout status deployment/edgepacer-opted-in "--timeout=${rollout_timeout}"
  run kubectl -n "${sample_namespace}" rollout status deployment/edgepacer-not-opted-in "--timeout=${rollout_timeout}"
}

print_diagnostics() {
  if [[ "${dry_run}" -eq 1 || "${render_only}" -eq 1 ]]; then
    return
  fi

  log ""
  log "Cluster diagnostics"
  kubectl get nodes -o wide || true

  if [[ "${install_agent}" -eq 1 ]]; then
    log ""
    log "EdgePacer DaemonSet"
    kubectl -n "${namespace}" get daemonset,pods -l "$(edgepacer_daemonset_selector)" -o wide || true
    kubectl -n "${namespace}" logs -l "$(edgepacer_daemonset_selector)" --tail=80 --prefix=true || true
  fi

  if [[ "${deploy_samples}" -eq 1 ]]; then
    log ""
    log "Sample workloads"
    kubectl -n "${sample_namespace}" get pods -o wide --show-labels || true
    log "Sample opt-in metadata"
    printf 'edgepacer-opted-in\t' >&2
    kubectl -n "${sample_namespace}" get deployment edgepacer-opted-in -o go-template='annotation={{ with .spec.template.metadata.annotations }}{{ index . "logpacer.com/service-name" }}{{ else }}<none>{{ end }} label={{ with .spec.template.metadata.labels }}{{ index . "logpacer.com/service-name" }}{{ else }}<none>{{ end }}{{ "\n" }}' || true
    printf 'edgepacer-not-opted-in\t' >&2
    kubectl -n "${sample_namespace}" get deployment edgepacer-not-opted-in -o go-template='annotation={{ with .spec.template.metadata.annotations }}{{ index . "logpacer.com/service-name" }}{{ else }}<none>{{ end }} label={{ with .spec.template.metadata.labels }}{{ index . "logpacer.com/service-name" }}{{ else }}<none>{{ end }}{{ "\n" }}' || true
    kubectl -n "${sample_namespace}" logs deployment/edgepacer-opted-in --tail=5 || true
    kubectl -n "${sample_namespace}" logs deployment/edgepacer-not-opted-in --tail=5 || true
  fi

  cat >&2 <<EOF

Expected validation:
- opted-in workload has annotation and label logpacer.com/service-name=edgepacer-validation-opted-in
- non-opted-in workload has no LogPacer opt-in metadata
- default local mode validates scheduling, RBAC, Helm packaging, trace Service/NetworkPolicy rendering, and sample log generation
- --require-agent-ready adds the strict image/token/backend readiness check
EOF
}

cleanup_resources() {
  if [[ "${use_existing_cluster}" -eq 0 ]]; then
    if [[ "${dry_run}" -eq 1 ]]; then
      run kind delete cluster --name "${cluster_name}"
    elif kind_cluster_exists; then
      run kind delete cluster --name "${cluster_name}"
    else
      log "No kind cluster found: ${cluster_name}"
    fi
    return
  fi

  run helm uninstall "${release_name}" --namespace "${namespace}" --ignore-not-found
  run kubectl -n "${namespace}" delete secret "${secret_name}" --ignore-not-found
  run kubectl delete namespace "${sample_namespace}" --ignore-not-found
}

main() {
  parse_args "$@"
  normalize_args

  if [[ "${cleanup_only}" -eq 1 ]]; then
    check_cleanup_prerequisites
    cleanup_resources
    return
  fi

  check_prerequisites

  render_chart

  if [[ "${render_only}" -eq 1 ]]; then
    return
  fi

  ensure_cluster

  if [[ "${install_agent}" -eq 1 ]]; then
    install_edgepacer
  fi

  if [[ "${deploy_samples}" -eq 1 ]]; then
    deploy_sample_workloads
  fi

  print_diagnostics

  if [[ "${delete_cluster_on_exit}" -eq 1 && "${cluster_created}" -eq 0 ]]; then
    log "Cluster was not created by this run; leaving it in place. Use --cleanup to delete ${cluster_name}."
  fi
}

main "$@"
