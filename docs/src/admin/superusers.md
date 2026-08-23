# Trusted superusers

`nas_admin` is the only Authentik group marked `is_superuser`. The initial bootstrap places `akadmin` in this group when it has no members. There is one trusted superuser by default, but the group may contain multiple enabled users.

Every member is fully trusted and can effectively administer Authentik-protected NAS applications, CopyParty, Syncthing, and the upstream administrative interfaces exposed to administrators. Do not use `nas_admin` for ordinary delegation. Direct Cockpit and locked-state access additionally requires an intentionally provisioned local Linux/PAM administrator account.

## Add another superuser

1. Sign in to the Authentik Admin interface.
2. Create or select the user.
3. Require strong MFA and verify recovery information.
4. Add the user explicitly to `nas_admin`.
5. Run **Validate identity model** in Cockpit or `sudo nas-identity-sync status`.

Authentik superuser state is intentionally derived from explicit membership in the superuser group. A bare `is_superuser` value on a user object is not accepted as NAS administration authority.

## Remove a superuser

1. Confirm at least one other enabled `nas_admin` member exists.
2. Remove the user from `nas_admin` or deactivate the user.
3. Revoke active sessions and application tokens in Authentik.
4. Rotate any secrets the administrator could have copied when appropriate.
5. Validate the identity model.

The reconciler fails closed when there are no enabled explicit members. It does not limit the group to one member.

## Bootstrap recovery

If the group is empty during bootstrap, the appliance attempts to add the enabled `akadmin` account through Authentik's group-membership API. If `akadmin` is absent or disabled, activation reports an explicit recovery error rather than inferring administration from a user flag.

## Cockpit and locked-state access

`nas_admin` grants NAS application and Cockpit administration after Authentik is running. Adding an Authentik superuser does not create a local recovery account. Provision local console, SSH, or KVM recovery access separately.
