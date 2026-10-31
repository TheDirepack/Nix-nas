# Headless GUI: initial Xvfb isolation probe

This is *developer evidence for issue #104*, **not** an implemented Managed Services V2 GUI feature. The `scripts/headless_gui_xvfb_probe.py` helper starts one disposable X11 display with a private MIT-MAGIC-COOKIE file, no TCP listener, automatic cleanup, and an optional screenshot. It does **not** start the display as a V2 service, supply container isolation, expose an MCP API, or prove installed NixOS behavior.

## Local commands

Requires `Xvfb`, `xauth`, and `xdpyinfo`. To exercise the screenshot code, install Pillow; the GUI-window test also needs `xterm`.

```sh
python3 -m unittest -v tests/test_headless_gui_xvfb_probe.py
python3 scripts/headless_gui_xvfb_probe.py --screenshot /tmp/xvfb-smoke.png
```

The test suite skips the whole integration group if Xvfb / Xauthority tools are missing, rather than making the regular host/unit suite depend on a display server. The actual-window and screenshot checks are skipped if their optional components are unavailable.

### What the probe checks

- Fresh, private 0700 runtime directory and 0600 Xauthority cookie, created before Xvfb starts. The cookie is fed via `stdin` to `xauth`, not exposed in a command-line argument. No `-ac` access-control bypass.
- The display is ready only after an authorized X11 client (`xdpyinfo`) connects. An invalid cookie is rejected.
- An X11 GUI window (`xterm`) is actually rendered and changes captured pixels, not merely a successful server start.
- Two independent displays can coexist with different cookies; cross-using their credentials fails.
- Exiting the context terminates the owned Xvfb process and removes its temporary credentials. The probe does not stop unrelated X11 servers and retries a random-display collision.

### Remaining qualification (do not assert as passed)

- NixOS package/closure selection and normal V2 `schema → effective → projection → apply` integration.
- OCI/Podman isolation with unprivileged users, networks, persistent per-app state, GPU/Wayland/AT-SPI, and systemd unit lifecycle.
- Safe native per-app private socket directories, sandbox policies, verified no cross-app filesystem mounts, and startup under actual V2 resource limits.
- Headless Weston, labwc/wayvnc, Selkies/pixelflux viewer/control and authenticator configurations. These candidates remain separate comparisons, not consequences of this Xvfb smoke test.
- X11 process tree and runtime cleanup following SIGKILL/host reboot, container restart, and orphaned processes.

After the local probe, the next change should be a **NixOS/Podman disposable VM scenario** that checks the same auth, display startup, GUI, capture and cleanup assertions under actual V2 runtime semantics. Do not wire GUI display servers into protected production services until that evidence exists.
