#!/usr/bin/env bash
# Wrapper that transparently decrypts .env.enc with sops before running docker compose.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"
ENV_FILE="${REPO_ROOT}/.env"
ENV_FILE_ENC="${REPO_ROOT}/.env.enc"
AGE_KEY_FILE="${SOPS_AGE_KEY_FILE:-${REPO_ROOT}/secrets/age.key}"

load_env_file() {
  local file_path="$1"
  if [[ ! -f "${file_path}" ]]; then
    return
  fi

  set -a
  # shellcheck source=/dev/null
  source "${file_path}"
  set +a
}

if [[ -f "${ENV_FILE_ENC}" ]]; then
  if ! command -v sops >/dev/null 2>&1; then
    >&2 echo "[ERROR] sops is required to decrypt ${ENV_FILE_ENC}."
    exit 1
  fi

  if [[ ! -f "${AGE_KEY_FILE}" ]]; then
    >&2 echo "[ERROR] Age key not found at ${AGE_KEY_FILE}."
    exit 1
  fi

  tmp_env=$(mktemp)
  SOPS_AGE_KEY_FILE="${AGE_KEY_FILE}" sops --decrypt "${ENV_FILE_ENC}" > "${tmp_env}"
  load_env_file "${tmp_env}"
  rm -f "${tmp_env}"
else
  load_env_file "${ENV_FILE}"
fi

cd "${REPO_ROOT}/infra"
exec docker compose "$@"
