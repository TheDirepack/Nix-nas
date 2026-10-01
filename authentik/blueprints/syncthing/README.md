# Syncthing blueprints

Syncthing-specific Authentik objects live here instead of being mixed into the appliance-wide identity blueprint.

Each file in this directory is deliberately self-contained. Authentik does not guarantee discovery order between blueprint files, so a blueprint must not depend on an object created by a sibling file unless it uses Authentik's blueprint dependency/meta-model mechanism.

`nas-syncthing-user-settings.yaml` contains the user-editable Syncthing device prompt, validation policy, write stage, and settings flow. It is staged with automatic instantiation disabled until the old combined `nas-user-settings.yaml` blueprint is removed and the runtime packaging switches to this directory.
