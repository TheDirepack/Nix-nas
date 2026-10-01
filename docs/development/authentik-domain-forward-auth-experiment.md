# Authentik domain forward-auth experiment

This is a disposable-VM proof for replacing the three fixed proxy-provider transactions currently owned by `nas_identity_sync.py`. It is not enabled by the appliance and must not be applied to a real installation as part of this PR.

## Question being tested

Can the pinned Authentik version use one `forward_domain` proxy provider for the NAS public host while Caddy continues to enforce route-level authorization, with providerless Authentik applications supplying only launcher tiles?

The upstream limitation is intentional: a domain-level Authentik provider cannot enforce different application-level authorization rules. That is acceptable only if Caddy's existing generated capability checks remain the sole route authorization boundary.

## Disposable-VM procedure

1. Start a fresh project VM with the normal installer/test wrapper and complete first-start.
2. Copy `authentik/experiments/nas-domain-forward-auth.yaml` to a temporary file and replace every `nas.example.invalid` with the VM's browser-reachable public host (without a port in `cookie_domain`).
3. Apply the temporary blueprint with the pinned `ak apply_blueprint` command as the Authentik service identity.
4. Assign only the experimental domain provider to the embedded proxy outpost. Do not remove the production providers yet.
5. Configure a temporary Caddy test route to use the domain-forward-auth endpoint while retaining the same Caddy capability matcher used by the production route.
6. Exercise an administrator, an ordinary user with the required application capability, an authenticated user without that capability, and an unauthenticated browser.
7. Restart Authentik and the embedded outpost, then repeat the route probes without reapplying the blueprint.
8. Exercise locked boot -> unlock, first-start setup retirement, and identity replacement. Verify the launcher tiles still point at `/`, `/console/`, and `/setup/` as applicable and that a retired setup tile cannot reappear.
9. Apply a deliberately invalid blueprint update and verify the existing provider/app objects remain usable after the failed transaction.

## Acceptance required before deleting REST reconciliation

- unauthenticated requests redirect through Authentik;
- authenticated users without the route capability receive Caddy's denial and cannot rely on the domain provider to bypass it;
- authorized users reach each protected route;
- providerless launcher applications open the correct public paths;
- the embedded outpost works after clean boot without a manual repair step;
- first-run setup retirement removes setup access and the setup launcher;
- relock/unlock and replacement of the bootstrap identity still work;
- failed blueprint application does not leave a half-mutated provider/outpost/application set.

Only after all of those pass should a second PR delete `_ensure_proxy_application`, the three fixed provider CRUD transactions, and their rollback machinery. The bootstrap operation that adds `akadmin` to an otherwise empty administrator group remains stateful and is outside this experiment.
