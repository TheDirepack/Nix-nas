# Headless GUI: initial Xvfb isolation probe

This is *developer evidence for issue #104*, **not** an implemented Managed Services V2 GUI feature. The `scripts/headless_gui_xvfb_probe.py` helper starts one disposable X11 display with a private MIT-MAGIC-COOKIE file, no TCP listener, automatic cleanup, and an optional bounded screenshot. It does **not** start the display as a V2 service, supply container isolation, expose an MCP API, or prove installed NixOS behavior.

## Local commands

Requires `Xvfb`, `xauth`, and `xdpyinfo`. To exercise the screenshot code, install Pillow; the GUI-window tests also need `xterm`.

```sh
python3 -m unittest -v tests/test_headless_gui_xvfb_probe.py
python3 scripts/headless_gui_xvfb_probe.py --screenshot /tmp/xvfb-smoke.png
```

The test suite skips the integration group if Xvfb / Xauthority tools are missing, rather than making the regular host/unit suite depend on a display server. The actual-window, capture and screenshot checks skip if their optional components are unavailable; three dependency-free contracts still run on every host.

### What the probe checks

- Xvfb chooses and reports its display through the upstream `-displayfd` interface. The probe never scans for a random display number and never treats a successful `xdpyinfo` alone as proof that the server is private: it requires the display number to be absent from the pre-spawn socket/lock set and the socket to belong to the session's effective UID before yielding it. A pre-existing unauthenticated server is therefore never adopted.
- Readiness starts with a private 0700 runtime directory and a 0600 Xauthority file created before Xvfb starts. Once Xvfb reports its display, the per-display cookie is written through `xauth` on standard input, so it never appears in a command-line argument. No `-ac` access-control bypass.
- The startup deadline bounds the display allocation wait, the socket wait and every readiness client attempt. Each `xdpyinfo` timeout is the smaller of one second and the remaining outer budget, so a slow client cannot extend startup past the requested bound.
- Xvfb diagnostics go to a private log file, not an unread pipe. A server that logs heavily therefore cannot block on a full stderr pipe while the session is in use, and the log is removed with the private directory.
- Capture runs Pillow's X11 backend in a child process that receives the session's `DISPLAY` and `XAUTHORITY`. The parent process environment is never mutated, so concurrent captures cannot cross displays, and a hung backend is killed at a 10-second deadline instead of hanging the caller.
- An X11 GUI window (`xterm`) is actually rendered and changes captured pixels. Two concurrent sessions render two different `xterm` windows; concurrent captures show each display's own window and never the other's.
- Two independent displays can coexist with different cookies; re-keying B's real cookie under A's display name is rejected by A.
- Exiting the context terminates the owned Xvfb process, reaps it, and removes its temporary credentials. If the caller has already SIGKILLed the server, the context also removes the display socket it created once nothing is listening on it. It never touches a display socket or lock that predates the session, that a live process still serves, or whose lock names another process.

### Test inventory

`tests/test_headless_gui_xvfb_probe.py` contains 19 tests:

- Four contracts, three of which run without any X11 tooling (invalid geometry, missing tools, bounded screenshot deadline). The fourth proves a timed-out readiness client is retried within the outer deadline.
- Fifteen real-display checks covering pre-existing-display rejection, `-displayfd` delegation, bounded readiness, stderr backpressure, SIGKILL artifact cleanup, foreign-artifact safety, authentication, capture isolation, GUI pixel change, concurrent GUI isolation, credential separation and cleanup on normal, killed and exception paths.

The repository test runner rejects an all-skipped test file, so the three dependency-free contracts keep this file runnable without a display server.

### Remaining qualification (do not assert as passed)

- NixOS package/closure selection and normal V2 `schema → effective → projection → apply` integration.
- OCI/Podman isolation with unprivileged users, networks, persistent per-app state, GPU/Wayland/AT-SPI, and systemd unit lifecycle.
- Safe native per-app private socket directories, sandbox policies, verified no cross-app filesystem mounts, and startup under actual V2 resource limits.
- Headless Weston, labwc/wayvnc, Selkies/pixelflux viewer/control and authenticator configurations. These candidates remain separate comparisons, not consequences of this Xvfb smoke test.
- X11 process-tree and runtime cleanup after host reboot, container restart, orphaned processes, and concurrent probes on a host with unusual `/tmp` permissions. The local SIGKILL path only proves the socket/lock cleanup performed by this probe.

After the local probe, the next change should be a **NixOS/Podman disposable VM scenario** that checks the same auth, display startup, GUI, capture and cleanup assertions under actual V2 runtime semantics. Do not wire GUI display servers into protected production services until that evidence exists.
