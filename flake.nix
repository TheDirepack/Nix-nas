{
  description = "NixOS NAS 2.2.0-alpha.35 appliance with ZFS, Authentik, CopyParty, on-demand services, and integrated operations";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";

    copyparty = {
      url = "github:9001/copyparty";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      copyparty,
      ...
    }:
    let
      system = "x86_64-linux";
      mkPkgs = systemName: import nixpkgs {
        system = systemName;
        overlays = [ copyparty.overlays.default ];
        config.allowUnfreePredicate = package: nixpkgs.lib.getName package == "open-webui";
      };
      commonModules = [
        self.nixosModules.default
        ./local.nix
      ];
      mkConsumer = extraModules: nixpkgs.lib.nixosSystem {
        inherit system;
        modules = [
          self.nixosModules.default
          ./tests/nixos/hardware-configuration.nix
          ./tests/nixos/module-consumer.nix
        ] ++ extraModules;
      };
    in
    {
      nixosModules = rec {
        core = import ./modules/nas;
        ai = import ./modules/ai;
        default = { ... }: {
          imports = [
            copyparty.nixosModules.default
            ai
            core
          ];
          nixpkgs.overlays = [ copyparty.overlays.default ];
        };
        profiles = {
          core-storage = import ./modules/profiles/core-storage.nix;
          identity-sharing = import ./modules/profiles/identity-sharing.nix;
          observability = import ./modules/profiles/observability.nix;
          virtualization = import ./modules/profiles/virtualization.nix;
          local-ai = import ./modules/profiles/local-ai.nix;
          all = import ./modules/profiles/all.nix;
        };
      };

      nixosConfigurations.nas = nixpkgs.lib.nixosSystem {
        inherit system;
        modules = commonModules ++ [ ./hardware-configuration.nix ];
      };

      nixosConfigurations.nas-ci-ready = nixpkgs.lib.nixosSystem {
        inherit system;
        modules = commonModules ++ [
          ./tests/nixos/hardware-configuration.nix
          ./tests/nixos/ready.nix
        ];
      };

      nixosConfigurations.nas-qemu = nixpkgs.lib.nixosSystem {
        system = "x86_64-linux";
        modules = commonModules ++ [ ./tests/nixos/qemu-installed.nix ];
      };

      nixosConfigurations.nas-module-consumer = mkConsumer [ ];
      nixosConfigurations.nas-profile-core-storage = mkConsumer [ self.nixosModules.profiles."core-storage" ];
      nixosConfigurations.nas-profile-identity-sharing = mkConsumer [ self.nixosModules.profiles."identity-sharing" ];
      nixosConfigurations.nas-profile-observability = mkConsumer [ self.nixosModules.profiles.observability ];
      nixosConfigurations.nas-profile-virtualization = mkConsumer [ self.nixosModules.profiles.virtualization ];
      nixosConfigurations.nas-profile-local-ai = mkConsumer [ self.nixosModules.profiles."local-ai" ];
      nixosConfigurations.nas-profile-all = mkConsumer [ self.nixosModules.profiles.all ];

      checks.x86_64-linux =
        let pkgs = mkPkgs "x86_64-linux";
        in {
          nas-vm = import ./tests/nixos/integration.nix {
            inherit pkgs self copyparty;
          };
          nas-vm-encrypted = import ./tests/nixos/encrypted.nix {
            inherit pkgs self copyparty;
          };
        };

      # Reusable Nix store roots for the QEMU integration VMs. The full VM
      # system closure is thousands of store paths; fetching them one at a
      # time through the Magic Nix Cache trips GitHub's per-path cache rate
      # limit. The core root contains boot, recovery, unlock, primary access,
      # and deterministic-test tooling. Optional applications remain separate
      # roots so a change to one application does not invalidate the others.
      packages.x86_64-linux =
        let
          pkgs = mkPkgs "x86_64-linux";
          # The vaultwarden systemd unit runs the package with dbBackend="sqlite"
          # (see modules/nas/config/application-services.nix), so the bundled
          # derivation must be the same override the module produces.
          vaultwardenBundle = pkgs.vaultwarden.override { dbBackend = "sqlite"; };
          # The cockpit-zfs plugin is built with Node 22 as a workaround for
          # NixOS/nixpkgs#530137 (see modules/nas/internal/zfs-tools.nix).
          cockpitZfsBuildPackages = pkgs.buildPackages // {
            yarn-berry = pkgs.buildPackages.yarn-berry.override {
              nodejs = pkgs.buildPackages.nodejs_22;
            };
          };
          cockpitZfsBundle = pkgs.cockpit-zfs.override {
            nodejs = pkgs.nodejs_22;
            yarn-berry = pkgs.yarn-berry.override { nodejs = pkgs.nodejs_22; };
            buildPackages = cockpitZfsBuildPackages;
          };
          # The integration VM enables TFTP, which adds partftpy to the
          # CopyParty runtime. Keep the exported core root aligned with the
          # package used by the VM service rather than exporting an incomplete
          # unconfigured CopyParty closure.
          copypartyBundle = pkgs.copyparty.overridePythonAttrs (old: {
            dependencies = old.dependencies ++ [ pkgs.python3Packages.partftpy ];
          });
          bundlePaths = with pkgs; {
            core = [
              bash
              cacert
              caddy
              chromium
              coreutils
              curl
              diffutils
              findutils
              gawk
              git
              gnugrep
              gnused
              iproute2
              jq
              keepassxc
              linuxPackages.kernel
              nodejs
              openssh
              procps
              (python3.withPackages (pythonPackages: [ pythonPackages.hypothesis pythonPackages.selenium ]))
              sanoid
              smartmontools
              pciutils
              vim
              skopeo
              systemd
              util-linux
              zfs
              copypartyBundle
              chromedriver
            ];
            identity = [ authentik postgresql vaultwardenBundle syncthing ];
            observability = [ grafana ntfy-sh ];
            storage = [ restic cockpit-files cockpit-podman cockpitZfsBundle ];
            ai = [ open-webui llama-swap llama-cpp ];
          };
        in {
          core = pkgs.buildEnv {
            name = "nas-vm-bundle-core";
            paths = bundlePaths.core;
          };
          identity = pkgs.buildEnv {
            name = "nas-vm-bundle-identity";
            paths = bundlePaths.identity;
          };
          observability = pkgs.buildEnv {
            name = "nas-vm-bundle-observability";
            paths = bundlePaths.observability;
          };
          storage = pkgs.buildEnv {
            name = "nas-vm-bundle-storage";
            paths = bundlePaths.storage;
          };
          ai = pkgs.buildEnv {
            name = "nas-vm-bundle-ai";
            paths = bundlePaths.ai;
          };
          vm-drivers = pkgs.buildEnv {
            name = "nas-vm-bundle-vm-drivers";
            paths = [ ];
          };
        };

      devShells.x86_64-linux.test =
        let pkgs = mkPkgs "x86_64-linux";
        in pkgs.mkShell {
          packages = [
            (pkgs.python3.withPackages (pythonPackages: with pythonPackages; [
              bandit
              coverage
              hypothesis
              selenium
            ]))
            pkgs.semgrep
            pkgs.shellcheck
            pkgs.actionlint
            pkgs.nodejs
            pkgs.pyright
            pkgs.ruff
          ];
          shellHook = ''
            echo "NixOS NAS security, property, and fuzz test tools are available." >&2
          '';
        };

      devShells.x86_64-linux.qemu-test =
        let pkgs = mkPkgs "x86_64-linux";
        in pkgs.mkShell {
          packages = with pkgs; [
            bats
            coreutils
            curl
            expect
            git
            gnutar
            jq
            libarchive
            openssh
            python3
            qemu
          ];
          shellHook = ''
            echo "NixOS NAS QEMU tools are available." >&2
            echo "Run: ./scripts/qemu-test.sh all" >&2
          '';
        };
    };
}
