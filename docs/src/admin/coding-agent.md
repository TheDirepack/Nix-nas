# Pi coding agent

Nix OS NAS can optionally install the Pi coding agent as a **transient, sandboxed coding session**. Alpha.5 adds the core integration and security boundary; it does not add a second model router or a permanent coding daemon.

## Architecture

The model path is deliberately single-authority:

```text
Pi -> llama-swap -> hosted provider or local llama.cpp backend
```

Pi receives only a local llama-swap client credential. Upstream provider credentials remain readable only by the llama-swap service. Pi's own project-trust feature is useful for deciding whether to load repository-local Pi extensions/settings, but it is not the host security boundary; Nix OS NAS uses a dedicated `nas-code-agent` identity and transient systemd sandboxing for that boundary.

## Enable

```nix
nas.ai.codingAgent = {
  enable = true;
  workspaceRoots = [ "/srv/code" ];
};
```

This release uses the `pi-coding-agent` package already present in the pinned nixpkgs input. At the Alpha.5 pin it is built from the maintained `earendil-works/pi` source; no runtime npm install or separate Pi overlay is required. Evaluation fails with an explicit assertion if the pinned package disappears.

After activating secrets, an administrator can start an interactive session with:

```text
sudo nas-code /srv/code/my-project
```

Arguments after `--` are passed to Pi.

## Isolation

Each session is started with `systemd-run` as `nas-code-agent`. The transient service uses `NoNewPrivileges`, a strict system view, private temporary/device namespaces, kernel/control-group protections, a loopback-only network policy, and writable-path allowlisting limited to the chosen workspace and coding-agent state directory. Workspace paths are canonicalized before launch; symlink escapes outside configured roots are rejected. The writable-path boundary does not make every world-readable host path inaccessible.

The local coding credential is transported using a systemd credential. It is intentionally not a provider credential.

## Model roles

Pi sees stable role IDs such as `coding/default`, `coding/cheap`, `coding/planner`, `coding/reviewer`, `coding/research`, and `coding/local-worker`. Those IDs must map to models in the NAS-owned llama-swap configuration. This keeps provider/model changes out of Pi policy.

The normal reasoning tier should be inexpensive hosted models. `coding/local-worker` is intended for bounded mechanical work suitable for the available <=9B local model.

## Configure hosted and remote models in Cockpit

Alpha.5 adds a structured **AI configuration** section to the NAS Cockpit page. Runtime model/provider policy is edited there rather than by hand-editing Pi or Open WebUI configuration.

llama-swap's upstream `peers` feature is the remote-provider mechanism. A peer can be OpenRouter, OpenAI, Groq, DeepSeek, another llama-swap instance, or another service that implements the `/v1` generative API surface llama-swap supports. The GUI exposes:

- NAS-managed local GGUF models, including model path, context size, idle TTL, tool-calling capability, and validated extra `llama-server` argv;
- provider ID and OpenAI-compatible base URL;
- the provider model allowlist;
- provider API-key creation/replacement through KeePassXC;
- connect, keepalive, response-header, TLS-handshake, and idle-connection timeouts;
- peer `stripParams` and JSON `setParams` request filters;
- coding role targets, ordered fallbacks, and `warm`, `pin`, or `spillover` selector strategy;
- safe global llama-swap health, default model idle TTL, unload grace, log, capture, and metrics settings.

The API key is never written into `config.yaml`. Cockpit sends it to the privileged backend over stdin; the backend stores it as `ai-provider-<id>` in KeePass and llama-swap references the staged key through an environment macro such as `${env.LLAMA_SWAP_PEER_OPENROUTER_API_KEY}`. Pi continues to receive only its local llama-swap client credential.

Open WebUI also has its own provider-connections UI, but Nix OS NAS intentionally does **not** use those connections as the appliance provider authority. Doing so would create a second credential/routing plane and Pi would not share it. Open WebUI remains a client of llama-swap, so remote models configured in Cockpit can be shared by both chat and coding workflows.

### What remains declarative NixOS configuration

The GUI does not rewrite trusted host policy. Enabling the coding-agent package, service UIDs, ports, approved workspace roots, extension installation, and systemd sandbox policy remain Nix options and require a rebuild. Everything intended to be mutable at runtime—local GGUF model definitions, provider endpoints/keys, remote model lists, model-role routing, and supported llama-swap runtime tuning—is available through Cockpit. Models already present in `config.yaml` without the NAS ownership marker are shown as manual/read-only entries so Cockpit cannot silently replace expert configuration.

## Extensions

The planned baseline is `pi-code`, `pi-web-access`, Context7's Pi extension, and `pi-lsp`. Alpha.5 does **not** fetch those packages at runtime: third-party Pi packages execute code with the agent's permissions, so they will be enabled only after exact versions and Nix dependency closures are pinned and qualified. Browser automation remains optional and lazy.

## Lifecycle

`aiCoding` is a child of `aiRuntime` and defaults to on-demand. The launcher wakes the feature and refreshes its activity timestamp while a session is alive. When the session ends, heartbeats stop and the existing feature reaper can return coding-specific resident RAM to zero.
