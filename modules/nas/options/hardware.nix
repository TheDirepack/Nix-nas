{ lib, ... }:

{
  options.nas = {
    hardware = {
      cpuVendor = lib.mkOption {
        type = lib.types.enum [ "auto" "amd" "intel" "other" ];
        default = "auto";
        description = "CPU vendor used for x86 microcode selection. ARM systems should use auto or other.";
      };
      gpuVendors = lib.mkOption {
        type = lib.types.listOf (lib.types.enum [ "intel" "amd" "nvidia" ]);
        default = [ ];
        description = "Installed GPU vendors. Intel and AMD use the normal Mesa stack; NVIDIA enables the NixOS NVIDIA driver.";
      };
      graphicsEnable = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = "Enable the NixOS graphics stack for local display, media acceleration, and Vulkan-capable drivers.";
      };
      nvidia = {
        openKernelModule = lib.mkOption {
          type = lib.types.bool;
          default = false;
          description = "Use NVIDIA's open kernel module when the selected GPU and driver support it.";
        };
        containerToolkit = lib.mkOption {
          type = lib.types.bool;
          default = false;
          description = "Enable NVIDIA Container Toolkit when GPU-enabled OCI workloads are required.";
        };
      };
    };
  };
}
