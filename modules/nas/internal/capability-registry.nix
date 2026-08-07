{ config, pkgs, ... }:

let
  cfg = config.nas;
  capabilityRegistry = {
    files = {
      id = "files";
      allowGroup = "nas_allow_files";
      denyGroup = "nas_deny_files";
      description = "Browse and use authenticated CopyParty file access.";
      owner = "copyparty";
      routes = [ "/shares/" ];
      administratorBypass = true;
      canWakeService = false;
      exposedInSetup = true;
      exposedInCockpit = true;
      authentikClaims = [ "groups" ];
      available = true;
    };
    webdav = {
      id = "webdav";
      allowGroup = "nas_allow_webdav";
      denyGroup = "nas_deny_webdav";
      description = "Use the CopyParty WebDAV endpoint.";
      owner = "copyparty";
      routes = [ "/dav/" ];
      administratorBypass = true;
      canWakeService = false;
      exposedInSetup = true;
      exposedInCockpit = true;
      authentikClaims = [ "groups" ];
      available = true;
    };
    ai = {
      id = "ai";
      allowGroup = "nas_allow_ai";
      denyGroup = "nas_deny_ai";
      description = "Use the AI workspace and authorized model APIs.";
      owner = "open-webui";
      routes = [ "/ai/" ];
      administratorBypass = true;
      canWakeService = true;
      exposedInSetup = true;
      exposedInCockpit = true;
      authentikClaims = [ "groups" ];
      available = cfg.ai.enable;
    };
    coding = {
      id = "coding";
      allowGroup = "nas_allow_coding";
      denyGroup = "nas_deny_coding";
      description = "Run the sandboxed Pi coding agent against approved repositories.";
      owner = "pi";
      routes = [ ];
      administratorBypass = true;
      canWakeService = true;
      exposedInSetup = true;
      exposedInCockpit = true;
      authentikClaims = [ "groups" ];
      available = cfg.ai.enable && cfg.ai.codingAgent.enable;
    };
    vault = {
      id = "vault";
      allowGroup = "nas_allow_vault";
      denyGroup = "nas_deny_vault";
      description = "Use the personal Vaultwarden service.";
      owner = "vaultwarden";
      routes = [ "/vault/" ];
      administratorBypass = true;
      canWakeService = false;
      exposedInSetup = true;
      exposedInCockpit = true;
      authentikClaims = [ "groups" ];
      available = cfg.vaultwarden.enable;
    };
    syncthing = {
      id = "syncthing";
      allowGroup = "nas_allow_syncthing";
      denyGroup = "nas_deny_syncthing";
      description = "Manage personal Syncthing devices and synchronized folders.";
      owner = "syncthing";
      routes = [ "/settings/syncthing" ];
      administratorBypass = true;
      canWakeService = false;
      exposedInSetup = true;
      exposedInCockpit = true;
      authentikClaims = [ "groups" ];
      available = cfg.syncthing.enable;
    };
  };
  capabilityRegistryDocument = {
    schemaVersion = 1;
    identityGroups = {
      administrator = "nas_admin";
      user = cfg.identity.userGroup;
      guest = cfg.identity.guestGroup;
      disabled = cfg.identity.disabledGroup;
    };
    capabilities = capabilityRegistry;
  };
  capabilityRegistryFile = pkgs.writeText "nas-capability-registry.json" (builtins.toJSON capabilityRegistryDocument);
in
{
  inherit capabilityRegistry capabilityRegistryDocument capabilityRegistryFile;
}
