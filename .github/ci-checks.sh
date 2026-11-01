# Shared GitHub Actions diagnostics helpers.
# This file is sourced by workflow steps; it is intentionally not an executable.
# shellcheck shell=bash

: "${CI_LOG_DIR:=ci-logs}"
: "${CI_RESULTS_FILE:=$CI_LOG_DIR/results.tsv}"
mkdir -p "$CI_LOG_DIR"

ci_run() {
  if (($# < 4)); then
    printf 'ci_run usage: ci_run <section> <slug> <label> <command> [args...]\n' >&2
    return 2
  fi

  local section=$1
  local slug=$2
  local label=$3
  shift 3

  if [[ ! "$section" =~ ^[A-Za-z0-9._-]+$ || ! "$slug" =~ ^[A-Za-z0-9._-]+$ ]]; then
    printf 'ci_run: unsafe section/slug: %q / %q\n' "$section" "$slug" >&2
    return 2
  fi

  local log="$CI_LOG_DIR/$section-$slug.log"
  local command_text start end elapsed rc results_rc
  local -a pipeline_status
  printf -v command_text '%q ' "$@"
  command_text=${command_text% }
  start=$(date +%s)

  printf '::group::%s\n' "$label"
  if "$@" 2>&1 | tee "$log"; then
    pipeline_status=("${PIPESTATUS[@]}")
  else
    pipeline_status=("${PIPESTATUS[@]}")
  fi
  rc=${pipeline_status[0]}
  if ((rc == 0)); then rc=${pipeline_status[1]}; fi
  printf '::endgroup::\n'

  end=$(date +%s)
  elapsed=$((end - start))
  if printf '%s\t%s\t%s\t%d\t%d\t%s\t%s\n' \
    "$section" "$slug" "$label" "$rc" "$elapsed" "$log" "$command_text" >> "$CI_RESULTS_FILE"; then
    :
  else
    results_rc=$?
    printf 'ci_run: unable to append results to %s (exit %d)\n' "$CI_RESULTS_FILE" "$results_rc" >&2
    if ((rc == 0)); then rc=$results_rc; fi
  fi

  if ((rc != 0)); then
    printf '::error title=%s::exit %d after %ds; full log: %s\n' "$label" "$rc" "$elapsed" "$log"
  fi
  return "$rc"
}
