{ lib, ... }:
{
  # module-consumer.nix forces autoUpdate off; this fixture must override it.
  nas.autoUpdate.enable = lib.mkOverride 10 true;
  nas.autoUpdate.apply = true;
}
