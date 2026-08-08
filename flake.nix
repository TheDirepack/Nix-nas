{
  description = "NixOS NAS 2.2.0-alpha.7 appliance with ZFS, Authentik, CopyParty, on-demand services, and integrated operations";

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
      mkPkgs = systemName: import nixpkgs { system = systemName; };
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

      devShells.x86_64-linux.test =
        let pkgs = mkPkgs "x86_64-linux";
        in pkgs.mkShell {
          packages = [
            (pkgs.python3.withPackages (pythonPackages: with pythonPackages; [
              bandit
              coverage
              hypothesis
            ]))
            pkgs.semgrep
            pkgs.shellcheck
          ];
          shellHook = ''
            echo "NixOS NAS security, property, and fuzz test tools are available."
          '';
        };

      devShells.x86_64-linux.qemu-test =
        let pkgs = mkPkgs "x86_64-linux";
        in pkgs.mkShell {
          packages = with pkgs; [
            bats
            curl
            expect
            jq
            libarchive
            openssh
            qemu
          ];
          shellHook = ''
            echo "NixOS NAS QEMU tools are available."
            echo "Run: ./scripts/qemu-test.sh all"
          '';
        };
    };
}
