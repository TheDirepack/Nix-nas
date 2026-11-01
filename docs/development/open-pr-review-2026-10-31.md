# Open pull-request review: shared CI blocker and bot findings (2026-10-31)

Scope: all 25 open draft pull requests #113–#137 (including non-sequential display order) in `TheDirepack/Nix-nas`, examined against their PR metadata, latest CodeRabbit conversation/inline comments, and CI run status. Individual findings below are **review hypotheses** until reproduced against each PR head. Do not silently apply a bot suggestion, change test policy, loosen CI, or claim appliance qualification.

## Shared, reproduced failure (fixed in this stack base)

Every inspected open PR has a failed latest CI workflow. The unit and unprivileged suites repeatedly fail at `tests/test_update_runtime.py:155`, where `test_invalid_probe_is_rejected_without_launch` expects two mutually exclusive diagnostics:
- Python's JSON-array validator rejects `{}` and emits `external probe command must be a nonempty JSON string array`.
- The shell waits for that process substitution, propagates the nonzero status, and exits **before** its secondary `External management probe command is empty` safeguard.

The rejection and no-launch behavior are correct; the *test oracle* is wrong. This branch corrects that regression: assert the actual fail-closed contract (exit 1, validator diagnostic, no fixture execution) across multiple invalid decoded shapes. It also keeps the existing main-baseline coverage-drift gate **required** when a dependent PR temporarily targets this shared-fix branch (both the workflow gate and `ci-summary.py` policy now agree). It does **not** weaken the production validator, skip a suite or relax the coverage threshold. Example latest evidence: [PR #137 unit CI](https://github.com/TheDirepack/Nix-nas/actions/runs/41208988000) and [PR #133 CI](https://github.com/TheDirepack/Nix-nas/actions/runs/41207553521). The unit failure also makes hermeticity fail and prevents a coverage report; PR coverage drift, qualification gate, and pipeline summary then fail or skip. These are cascading check states, not independent evidence of four production defects.

A new PR against this branch must re-run CI to prove whether **additional** failures remain. The 90-second hostile-login and scanner/installed-VM qualification blockers reported in other PR descriptions remain unresolved and are outside this patch.

## Cross-PR root-cause families

1. **Failure signaling / false success:** a successful-looking HTTP code can accompany a failed curl transfer (#129, #133); exit-code precedence and captured evidence must be explicit (#128, #134, #137). Where operations commit before a follow-up status check, report the committed mutation separately from query failure (#126). These belong in their own PR code paths, not in a generic catch-all wrapper.
2. **Fail-closed authority and state handling:** incomplete shape validation (#116, #123, #136), missing required files (#135), ambiguous API fallback (#130), and uncertain recovered ownership (#118, #124) can silently hide or misreport unsafe states. Their fixes must retain the owning component's trust boundary.
3. **Filesystem / process ownership:** canonical path and pruning safety (#122), private temporary trees (#127), PID/directory ownership (#125), and secret rollback recovery (#124) require real fixture and fault-injection tests.
4. **Test-oracle gaps:** several bots point out tests that only assert a generic failure, do not observe side effects, or omit important branches (#117, #118, #119, #125, #128, #134, #136). The shared validator test in this PR is a concrete example of a stale test expectation.
5. **Runtime projection/compatibility:** target ownership, transient restart staleness and fingerprint migration (#113), special socket-proxy address parsing (#121), and Compose included files and escaped interpolation (#123) are distinct and require version-aware/runtime evidence.

## Per-PR review inventory

| PR | Outstanding bot observation(s) at inspection | Disposition |
|---|---|---|
| [#113](https://github.com/TheDirepack/Nix-nas/pull/113) | Absent disabled target; transient units retain stale launch args; legacy fingerprint migration | Verify and fix on #113; high risk |
| [#114](https://github.com/TheDirepack/Nix-nas/pull/114) | Document HTTP 409 for unknown tracked-job state | Documentation fix on #114 |
| [#115](https://github.com/TheDirepack/Nix-nas/pull/115) | No actionable bot findings | Shared CI retest only |
| [#116](https://github.com/TheDirepack/Nix-nas/pull/116) | Reject malformed non-dict route entries instead of silently dropping routes | Verify and fix on #116 |
| [#117](https://github.com/TheDirepack/Nix-nas/pull/117) | Assert invalid replacement is rejected before Authentik API access | Strengthen #117 test |
| [#118](https://github.com/TheDirepack/Nix-nas/pull/118) | Retained-device and prepared-phase journal recovery coverage | Strengthen #118 tests |
| [#119](https://github.com/TheDirepack/Nix-nas/pull/119) | Verify successful request-time port resolution and changing ports | Strengthen #119 tests |
| [#120](https://github.com/TheDirepack/Nix-nas/pull/120) | No actionable bot findings | Shared CI retest only |
| [#121](https://github.com/TheDirepack/Nix-nas/pull/121) | Bot suggests unbracketed IPv6 for pinned socket-proxyd | Verify against actual **pinned** systemd parser; do not blindly reverse fix |
| [#122](https://github.com/TheDirepack/Nix-nas/pull/122) | Relative generation root could prune active generation | Verify and fix on #122; high risk |
| [#123](https://github.com/TheDirepack/Nix-nas/pull/123) | Compose `include` bypass; raw-YAML interpolation check misses escaped values and rejects comments | Verify provider semantics and fix on #123 |
| [#124](https://github.com/TheDirepack/Nix-nas/pull/124) | Pre-swap cleanup failure can omit recovery-tree location | Verify and fix on #124 |
| [#125](https://github.com/TheDirepack/Nix-nas/pull/125) | Invalid-PID test cannot detect redirected mock `kill` | Strengthen #125 test |
| [#126](https://github.com/TheDirepack/Nix-nas/pull/126) | Commit can succeed before status query fails, misleading callers | Verify and fix on #126; high risk |
| [#127](https://github.com/TheDirepack/Nix-nas/pull/127) | World-writable test fixture permits symlink redirection of cleanup | Secure #127 fixture |
| [#128](https://github.com/TheDirepack/Nix-nas/pull/128) | No test for command failure and `tee` failure together | Strengthen #128 test |
| [#129](https://github.com/TheDirepack/Nix-nas/pull/129) | Response body file can retain a stale earlier probe's body | Verify and fix on #129 |
| [#130](https://github.com/TheDirepack/Nix-nas/pull/130) | No actionable bot findings | Shared CI retest only |
| [#131](https://github.com/TheDirepack/Nix-nas/pull/131) | No actionable bot findings | Shared CI retest only |
| [#132](https://github.com/TheDirepack/Nix-nas/pull/132) | No actionable bot findings | Shared CI retest only |
| [#133](https://github.com/TheDirepack/Nix-nas/pull/133) | A `200` status can survive failed curl transport; inherited proxy can bypass local loopback probe | Verify and fix on #133 |
| [#134](https://github.com/TheDirepack/Nix-nas/pull/134) | Descendant termination not proven through security runner's actual path | Strengthen #134 test |
| [#135](https://github.com/TheDirepack/Nix-nas/pull/135) | No actionable bot findings | Shared CI retest only |
| [#136](https://github.com/TheDirepack/Nix-nas/pull/136) | Malformed-shape tests assert only an arbitrary per-file error | Strengthen #136 test |
| [#137](https://github.com/TheDirepack/Nix-nas/pull/137) | No actionable bot findings | Shared CI retest only |

## Review/stack protocol

This common-fix PR targets `main`. The above 25 draft PRs should temporarily target this branch to express the dependency and obtain CI with the corrected common baseline. Retargeting alone **does not graft the base commit into their head histories**. Recheck each PR's changed-files diff and mergeability after retargeting, then merge this base first; restore/verify `main` as the target afterward. No dependent PR should be merged or labeled production-qualified merely because the common unit assertion was fixed. Resolve each PR's bot findings separately with its own tested commits.

While an individual PR targets a non-default branch, automatic CodeRabbit reviews may be skipped. Request a manual `@coderabbitai review` after materially changing those dependent PRs (notably #130 and #135), and read new inline findings before considering them ready. The temporary stacked-PR CI result is not a substitute for a final main-based coverage comparison: after the shared fix lands, restore the PR's base to `main`, push a new commit to its head to trigger fresh qualification, and explicitly confirm `PR coverage drift` passes against `main`. Do not use the stack's passing base as proof of final installed-VM qualification.
