# Shared GitHub Actions diagnostics helpers.
# This file is sourced by workflow steps; it is intentionally not an executable.
# shellcheck shell=bash

: "${CI_LOG_DIR:=ci-logs}"
: "${CI_RESULTS_FILE:=$CI_LOG_DIR/results.tsv}"
: "${CI_FAILED_RUNS_FILE:=$CI_LOG_DIR/failed-runs.tsv}"
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
  local command_text start end elapsed rc
  printf -v command_text '%q ' "$@"
  command_text=${command_text% }
  start=$(date +%s)

  printf '::group::%s\n' "$label"
  "$@" 2>&1 | tee "$log"
  rc=${PIPESTATUS[0]}
  printf '::endgroup::\n'

  end=$(date +%s)
  elapsed=$((end - start))
  printf '%s\t%s\t%s\t%d\t%d\t%s\t%s\n' \
    "$section" "$slug" "$label" "$rc" "$elapsed" "$log" "$command_text" >> "$CI_RESULTS_FILE"

  if ((rc != 0)); then
    if [[ ! -f "$CI_FAILED_RUNS_FILE" ]]; then
      printf 'section\tslug\tlabel\texit_code\telapsed\tlog_path\tcommand\n' > "$CI_FAILED_RUNS_FILE"
    fi
    printf '%s\t%s\t%s\t%d\t%d\t%s\t%s\n' \
      "$section" "$slug" "$label" "$rc" "$elapsed" "$log" "$command_text" >> "$CI_FAILED_RUNS_FILE"
    printf '::error title=%s::%s\n' \
      "ci_run FAILED" \
      "section=$section slug=$slug label=$label exit_code=$rc elapsed=${elapsed}s log=$log command=$command_text" >&2
  fi
  return "$rc"
}
