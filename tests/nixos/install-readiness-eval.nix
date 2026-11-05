{ lib }:

let
  keyedAdministrator = {
    group = "users";
    extraGroups = [ "nas-administrators" ];
    openssh.authorizedKeys.keys = [ "ssh-ed25519 TestFixtureOnlyKeyMaterial" ];
  };
  evaluate = {
    users ? { admin = keyedAdministrator; },
    groups ? { },
    settings ? { },
    enabled ? true,
    console ? false,
    ready ? true,
  }:
    let
      evaluated = import ../../modules/nas/config/install-readiness.nix {
        inherit lib;
        pkgs = { };
        config = {
          nas = {
            installationReady = ready;
            hostPolicy.consoleRecoveryVerified = console;
          };
          services.openssh = {
            enable = enabled;
            settings = { AllowGroups = [ "nas-administrators" ]; DenyGroups = null; } // settings;
          };
          users = {
            inherit users;
            groups = { nas-administrators.members = [ ]; } // groups;
          };
        };
      };
    in
    (builtins.head evaluated.config.assertions).assertion;
  checks = {
    supplementaryAdministrator = evaluate { };
    primaryAdministrator = evaluate {
      users.admin = keyedAdministrator // { group = "nas-administrators"; extraGroups = [ ]; };
    };
    explicitAdministratorMember = evaluate {
      users.admin = keyedAdministrator // { extraGroups = [ ]; };
      groups.nas-administrators.members = [ "admin" ];
    };
    unrelatedKeyExcluded = !(evaluate {
      users.other = keyedAdministrator // { extraGroups = [ "operators" ]; };
      settings.AllowGroups = [ "operators" ];
    });
    rootExcluded = !(evaluate {
      users.root = keyedAdministrator;
      settings.AllowGroups = [ "*" ];
    });
    disabledSshExcluded = !(evaluate { enabled = false; });
    missingKeyExcluded = !(evaluate {
      users.admin = keyedAdministrator // { openssh.authorizedKeys.keys = [ ]; };
    });
    otherAllowedGroupExcluded = !(evaluate { settings.AllowGroups = [ "operators" ]; });
    supplementaryAllowedGroup = evaluate {
      users.admin = keyedAdministrator // { extraGroups = [ "nas-administrators" "operators" ]; };
      settings.AllowGroups = [ "operators" ];
    };
    primaryAllowedGroup = evaluate {
      users.admin = keyedAdministrator // { group = "operators"; };
      settings.AllowGroups = [ "operators" ];
    };
    explicitAllowedGroupMember = evaluate {
      groups.operators.members = [ "admin" ];
      settings.AllowGroups = [ "operators" ];
    };
    unrestrictedNull = evaluate { settings.AllowGroups = null; };
    unrestrictedEmpty = evaluate { settings.AllowGroups = [ ]; };
    starWildcard = evaluate { settings.AllowGroups = [ "nas-*" ]; };
    questionWildcard = evaluate { settings.AllowGroups = [ "nas-administrato?s" ]; };
    caseSensitive = !(evaluate { settings.AllowGroups = [ "NAS-*" ]; });
    bracketCharactersAreLiteral = !(evaluate { settings.AllowGroups = [ "nas-[a]dministrators" ]; });
    exclamationIsLiteral = !(evaluate { settings.AllowGroups = [ "!nas-administrators" ]; });
    commaIsLiteral = !(evaluate { settings.AllowGroups = [ "other,nas-administrators" ]; });
    literalDenyWins = !(evaluate { settings.DenyGroups = [ "nas-administrators" ]; });
    wildcardDenyWins = !(evaluate { settings.DenyGroups = [ "nas-*" ]; });
    otherDenyDoesNotMatch = evaluate { settings.DenyGroups = [ "operators" ]; };
    supplementaryDenyWins = !(evaluate {
      users.admin = keyedAdministrator // { extraGroups = [ "nas-administrators" "operators" ]; };
      settings.DenyGroups = [ "operators" ];
    });
    primaryDenyWins = !(evaluate {
      users.admin = keyedAdministrator // { group = "operators"; };
      settings.DenyGroups = [ "operators" ];
    });
    explicitDenyMemberWins = !(evaluate {
      groups.operators.members = [ "admin" ];
      settings.DenyGroups = [ "operators" ];
    });
    consoleAttestationPreserved = evaluate { settings.AllowGroups = [ "operators" ]; console = true; };
    developmentNotGated = evaluate { users = { }; enabled = false; ready = false; };
  };
  failed = lib.attrNames (lib.filterAttrs (_: passed: !passed) checks);
in
assert lib.assertMsg (failed == [ ]) ("installation readiness cases failed: " + lib.concatStringsSep ", " failed);
checks
