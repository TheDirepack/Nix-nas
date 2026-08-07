args:
let
  inherit (args)
    cfg
    lib
    pkgs
  ;
  nasUpsInitPassword = pkgs.writeShellApplication {
    name = "nas-ups-init-password";
    runtimeInputs = [ pkgs.coreutils pkgs.openssl ];
    text = ''
      set -euo pipefail
      output=${lib.escapeShellArg cfg.power.ups.passwordFile}
      mode=${lib.escapeShellArg cfg.power.ups.mode}
      ups_enabled=${if cfg.power.ups.enable then "1" else "0"}

      if [[ "$ups_enabled" != "1" ]]; then
        echo "Enable nas.power.ups before creating its monitor password." >&2
        exit 1
      fi
      [[ $EUID -eq 0 ]] || {
        echo "Run this command through sudo so the boot-time secret remains root-owned." >&2
        exit 1
      }
      if [[ "$mode" == "netclient" ]]; then
        echo "Netclient mode must use the password configured on the remote NUT server; install that value manually at $output." >&2
        exit 1
      fi
      [[ ! -L "$output" ]] || { echo "Refusing to replace a symlink: $output" >&2; exit 1; }
      if [[ -e "$output" ]]; then
        identity="$(stat -c '%a:%U:%G' "$output")"
        [[ -f "$output" && -s "$output" && ( "$identity" == "400:root:root" || "$identity" == "600:root:root" ) ]] || {
          echo "Existing NUT password file is unsafe or empty: $output ($identity)" >&2
          exit 1
        }
        echo "NUT monitor password already exists and is root-only: $output"
        exit 0
      fi
      parent="$(dirname -- "$output")"
      install -d -m 0700 -o root -g root "$parent"
      tmp="$(mktemp "$parent/.nut-monitor-password.XXXXXX")"
      trap 'rm -f -- "$tmp"' EXIT
      chmod 0600 "$tmp"
      ${pkgs.openssl}/bin/openssl rand -hex 32 > "$tmp"
      install -m 0400 -o root -g root "$tmp" "$output"
      echo "Created the boot-available root-only NUT monitor password: $output"
    '';
  };
in
{
  inherit
    nasUpsInitPassword
  ;
}
