{ config, lib, ... }:

{
  nas.observability = {
    enable = lib.mkDefault true;
    grafana.enable = lib.mkDefault true;
    # Alerting requires a delivery target, but plain observability should not
    # keep another web daemon resident. Administrators can still explicitly
    # set nas.observability.ntfy.enable = true for standalone notifications.
    ntfy.enable = lib.mkDefault config.nas.alerting.enable;
  };
}
