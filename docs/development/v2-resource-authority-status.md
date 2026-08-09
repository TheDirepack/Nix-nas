# V2 resource-authority branch status

This is a live implementation branch stacked on PR #25.

## Implemented

- authoritative architecture boundary documented;
- shared storage-resource schema introduced;
- stable application-principal schema introduced;
- Authentik-managed capability-reference schema introduced.

## In progress

- wire the shared resource schemas into `managed-service.schema.json`;
- add migration/validation in `nas_managed_service.py`;
- convert service storage entries from inline host paths to resource references;
- derive effective runtime mounts from resource references plus authorization;
- remove embedded endpoint user/group assignment as an authority after migration;
- remove Cockpit Files and duplicated identity/capability UI;
- continue with Pi, backup/state, locking, Caddy, firewalld, Syncthing and libvirt simplifications.

This file is intentionally updated as checkpoints land so the stacked draft PR remains understandable while PR #25 continues changing underneath it.
