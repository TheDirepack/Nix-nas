#!/usr/bin/env bash

# Keep secrets in stdin. Callers must pass the command as argv, never as shell
# source, so quotes, expansion characters, and embedded newlines stay data.
nas_vm_run_with_secret_stdin() {
  local secret=$1
  shift
  printf '%s\n' "$secret" | "$@"
}
