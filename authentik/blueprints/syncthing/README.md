# Syncthing blueprints

Syncthing-specific Authentik objects live here instead of being mixed into the appliance-wide identity blueprint.

Each file in this directory is deliberately self-contained. Authentik does not guarantee discovery order between blueprint files, so a blueprint must not depend on an object created by a sibling file unless it uses Authentik's blueprint dependency/meta-model mechanism.

`nas-syncthing-user-settings.yaml` is the active user-editable Syncthing device prompt, validation policy, write stage, and settings flow. Runtime packaging retains the `nas-user-settings.yaml` path and blueprint name so existing installations update the same discovered blueprint and flow identifiers. The appliance-wide automation role lives separately in `../nas-automation.yaml`; neither blueprint depends on the other.
