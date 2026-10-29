# Native Cockpit D-Bus readiness fixtures

`source-manifest.json` binds complete, byte-exact upstream files to their Git
blobs and SHA256 hashes. Cockpit is commit
`ca0d360e3a858a7eb189edde15cf7b976018404b` (362); its `vendor/systemd_ctypes`
gitlink selects `a627fb8b2b58e6dead4ab85aa14abb41d1a48397` from
`allisonkarlitskaya/systemd_ctypes`. The vendored files retain their upstream
GPL-3.0-or-later notices; `COPYING` is the upstream license. Cockpit files retain
their GPL-3.0-or-later SPDX notices. These are test-only source fixtures, not an
additional runtime bridge.

The regression materializes the files privately, verifies every source digest,
applies the production source patch and imports the complete native channel,
router, protocol, JSON helpers and systemd binding. Only the enclosing Cockpit
package namespaces are synthetic, avoiding unrelated channel registration.
Injected failures and replies are confined to the Bus I/O boundary; a recording
transport observes native serialized frames. Native readiness, freezing,
thawing, task draining, endpoint removal and frame encoding are not mocked or
reimplemented. Loading the binding requires Linux `libsystemd.so.0`, supplied by
the test shell; tests do not connect to a host or guest bus.

An upstream update must refresh the immutable sources and manifest, recheck
patch applicability, and qualify the installed bridge. This fixture does not
explain a native `sd_bus_add_match` EINVAL, establish browser-timeout causation,
or qualify an installed package.
