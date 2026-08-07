{ lib, ... }:

{
  options.nas = {
    power = {
      cpuGovernor = lib.mkOption {
        type = lib.types.nullOr (lib.types.enum [ "performance" "powersave" "ondemand" "conservative" "schedutil" ]);
        default = null;
        description = "Optional CPU frequency governor. Null leaves platform defaults unchanged.";
      };
      ups = {
        enable = lib.mkOption {
          type = lib.types.bool;
          default = false;
          description = "Enable Network UPS Tools for local or network UPS monitoring and graceful shutdown.";
        };
        mode = lib.mkOption {
          type = lib.types.enum [ "standalone" "netserver" "netclient" ];
          default = "standalone";
          description = "NUT operation mode.";
        };
        name = lib.mkOption {
          type = lib.types.strMatching "^[A-Za-z0-9_.-]+$";
          default = "nas-ups";
          description = "NUT UPS identifier.";
        };
        description = lib.mkOption {
          type = lib.types.str;
          default = "NAS UPS";
          description = "Human-readable UPS description.";
        };
        driver = lib.mkOption {
          type = lib.types.str;
          default = "usbhid-ups";
          description = "NUT driver used in standalone or netserver mode.";
        };
        port = lib.mkOption {
          type = lib.types.str;
          default = "auto";
          description = "NUT driver port, commonly auto for USB HID UPS units.";
        };
        directives = lib.mkOption {
          type = lib.types.listOf lib.types.str;
          default = [ ];
          description = "Additional ups.conf directives for the local UPS driver.";
        };
        monitorSystem = lib.mkOption {
          type = lib.types.str;
          default = "";
          description = "Explicit upsmon system identifier for netclient mode, such as ups@server:3493.";
        };
        monitorUser = lib.mkOption {
          type = lib.types.strMatching "^[A-Za-z0-9_.-]+$";
          default = "nasmon";
          description = "NUT monitoring username.";
        };
        passwordFile = lib.mkOption {
          type = lib.types.str;
          default = "/etc/nixos/nixos-nas/secrets/nut-monitor-password";
          description = "Boot-available root-owned file containing the NUT monitor password.";
        };
        serverListenAddresses = lib.mkOption {
          type = lib.types.listOf lib.types.str;
          default = [ "127.0.0.1" "::1" ];
          description = "Addresses on which upsd listens in standalone or netserver mode.";
        };
        web = {
          enable = lib.mkOption {
            type = lib.types.bool;
            default = true;
            description = "Expose the upstream NUT Web GUI through the MFA-protected NAS portal when NUT is enabled.";
          };
          image = lib.mkOption {
            type = lib.types.str;
            default = "ghcr.io/superioone/nut_webgui:v0.9.2";
            description = "Versioned NUT Web GUI OCI image. Update deliberately after testing.";
          };
          port = lib.mkOption {
            type = lib.types.port;
            default = 9000;
            description = "Loopback NUT Web GUI HTTP port.";
          };
          upsdAddress = lib.mkOption {
            type = lib.types.str;
            default = "127.0.0.1";
            description = "NUT data server address used by NUT Web GUI. Set this explicitly for netclient mode.";
          };
          upsdPort = lib.mkOption {
            type = lib.types.port;
            default = 3493;
            description = "NUT data server port used by NUT Web GUI.";
          };
          allowControl = lib.mkOption {
            type = lib.types.bool;
            default = false;
            description = "Allow NUT Web GUI SET and instant-command actions. False provides monitoring-only credentials.";
          };
        };
      };
    };
  };
}
