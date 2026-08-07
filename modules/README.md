# Nix module layout

```text
modules/nas/options/   public `nas.*` option declarations
modules/nas/config/    NixOS implementation grouped by runtime concern
modules/nas/internal/  private builders, registries, constants, and shared helpers
modules/ai/            optional local-AI integration
```

Keep these boundaries simple:

- Public option definitions belong in `options/`, not implementation fragments.
- Keep a helper local until more than one fragment genuinely needs it.
- Export shared internal values through `internal/default.nix`; duplicate export names intentionally fail evaluation.
- Put feature metadata in `internal/feature-catalog.nix` and capability metadata in the central capability registry.
- Cross-process data should have a schema under `schemas/` when practical.
- Do not embed release notes, audit history, or operator tutorials in Nix expressions.

See `docs/development/architecture.md` and `docs/development/code-map.md` before adding another configuration authority.
