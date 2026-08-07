# User settings

Authentik owns ordinary account settings.

- **Password, MFA, sessions, and profile:** open `/settings/`.
- **Personal Syncthing devices:** open `/settings/syncthing`.

The Syncthing page stores `attributes.nasSyncthingDevices` on your Authentik account. A device list looks like:

```json
[
  {
    "name": "Laptop",
    "deviceID": "AAAAAAA-BBBBBBB-CCCCCCC-DDDDDDD-EEEEEEE-FFFFFFF-GGGGGGG-HHHHHHH",
    "addresses": ["dynamic"]
  }
]
```

The NAS validates the declaration and reconciles only your reserved `nas-*` Syncthing objects. Ordinary users cannot open the global Syncthing administration UI or edit another account's attributes.

File ACLs, quotas, volume flags, and share policy are not profile settings; administrators manage them in CopyParty.
