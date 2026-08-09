{ config, lib, pkgs, nasInternal, ... }:

let
  inherit (nasInternal)
    cfg
    hasAmdGpu
    hasIntelGpu
    hasNvidiaGpu
    isX86_64
    llamaBackend
    upsMonitorSystem
    upsUsesLocalDriver
  ;
in
{
  config = {
    nixpkgs.config.allowUnfreePredicate = lib.mkForce (package:
      let name = lib.getName package;
      in name == "open-webui" || (hasNvidiaGpu && lib.any (prefix: lib.hasPrefix prefix name) [
          "nvidia"
          "cuda"
          "cudnn"
          "libcu"
          "nccl"
        ]));
    nixpkgs.config.cudaSupport = lib.mkForce (llamaBackend == "cuda");
    nixpkgs.config.rocmSupport = lib.mkForce (llamaBackend == "rocm");
    networking.hostName = lib.mkDefault "nas";
    time.timeZone = lib.mkDefault "UTC";

    systemd.sleep.settings.Sleep = {
      AllowSuspend = "no";
      AllowHibernation = "no";
      AllowHybridSleep = "no";
      AllowSuspendThenHibernate = "no";
    };
    powerManagement = {
      enable = true;
      cpuFreqGovernor = cfg.power.cpuGovernor;
    };

    # UPS shutdown must work before secret activation.
    power.ups = lib.mkIf cfg.power.ups.enable {
      enable = true;
      mode = cfg.power.ups.mode;
      openFirewall = false;
      ups = lib.optionalAttrs upsUsesLocalDriver {
        "${cfg.power.ups.name}" = {
          driver = cfg.power.ups.driver;
          port = cfg.power.ups.port;
          description = cfg.power.ups.description;
          directives = cfg.power.ups.directives;
        };
      };
      users = lib.optionalAttrs upsUsesLocalDriver {
        "${cfg.power.ups.monitorUser}" = {
          passwordFile = cfg.power.ups.passwordFile;
          upsmon = "primary";
          actions = lib.optionals cfg.power.ups.web.allowControl [ "SET" "FSD" ];
          instcmds = lib.optionals cfg.power.ups.web.allowControl [ "ALL" ];
        };
      };
      upsmon = {
        monitor."${cfg.power.ups.name}" = {
          system = upsMonitorSystem;
          user = cfg.power.ups.monitorUser;
          passwordFile = cfg.power.ups.passwordFile;
          powerValue = 1;
          type = if cfg.power.ups.mode == "netclient" then "secondary" else "primary";
        };
        settings = {
          MINSUPPLIES = 1;
          NOTIFYFLAG = [
            [ "ONLINE" "SYSLOG" ]
            [ "ONBATT" "SYSLOG" ]
            [ "LOWBATT" "SYSLOG" ]
            [ "FSD" "SYSLOG" ]
            [ "SHUTDOWN" "SYSLOG" ]
            [ "COMMOK" "SYSLOG" ]
            [ "COMMBAD" "SYSLOG" ]
          ];
        };
      };
      upsd.listen = if cfg.power.ups.mode == "netserver" then
        map (address: { inherit address; port = 3493; }) cfg.power.ups.serverListenAddresses
      else
        [ { address = "127.0.0.1"; port = 3493; } { address = "::1"; port = 3493; } ];
    };
    boot.supportedFilesystems = [ "zfs" ];
    boot.zfs = {
      forceImportRoot = false;
      forceImportAll = false;
      extraPools = lib.optional cfg.zfsImportAtBoot cfg.zfsPool;
    };
    hardware.enableRedistributableFirmware = true;
    hardware.cpu.amd.updateMicrocode =
      isX86_64 && lib.elem cfg.hardware.cpuVendor [ "auto" "amd" ];
    hardware.cpu.intel.updateMicrocode =
      isX86_64 && lib.elem cfg.hardware.cpuVendor [ "auto" "intel" ];
    hardware.graphics.enable = cfg.hardware.graphicsEnable;
    hardware.nvidia = lib.mkIf hasNvidiaGpu {
      open = cfg.hardware.nvidia.openKernelModule;
      modesetting.enable = true;
      nvidiaSettings = false;
      powerManagement.enable = false;
    };
    hardware.nvidia-container-toolkit.enable =
      hasNvidiaGpu && cfg.hardware.nvidia.containerToolkit;
    services.xserver = lib.mkIf cfg.desktop.enable {
      enable = true;
      videoDrivers =
        lib.optional hasNvidiaGpu "nvidia"
        ++ lib.optional (hasIntelGpu || hasAmdGpu) "modesetting";
      displayManager.lightdm = {
        enable = true;
        greeters.gtk.enable = true;
      };
      desktopManager.xfce.enable = true;
    };
    services.displayManager.defaultSession = lib.mkIf cfg.desktop.enable "xfce";
    environment.etc."xdg/autostart/keepassxc.desktop" = lib.mkIf cfg.desktop.enable {
      text = ''
        [Desktop Entry]
        Type=Application
        Name=KeePassXC
        Comment=Open the NAS KeePassXC database for graphical maintenance
        Exec=${pkgs.keepassxc}/bin/keepassxc
        Terminal=false
        OnlyShowIn=XFCE;
        X-GNOME-Autostart-enabled=true
      '';
    };
  };
}
