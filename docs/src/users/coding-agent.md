# Coding agent

The optional Coding capability is separate from ordinary AI chat access because a coding agent can read/write source and run commands.

When enabled for your account, Pi can modify only an administrator-approved repository workspace and sends model requests through the NAS llama-swap service. It does not receive the NAS's hosted-provider API keys.

The initial Alpha.5 interface is administrator-launched (`sudo nas-code <workspace>`). Integration into the existing chat UI is the next UI phase; a separate always-running Pi web UI is intentionally not required.

## Local and remote/cloud models

Administrators can configure both NAS-managed local GGUF models and hosted OpenAI-compatible model providers from **Cockpit -> AI configuration**. Local models expose context, idle TTL, tool-calling capability, and validated extra llama-server arguments. Remote providers expose endpoint/model lists, secure KeePass-backed API keys, connection timeouts, and request filters.

All resulting model targets are routed through llama-swap, so the coding agent does not need or receive a cloud-provider API key. Coding model roles and fallback strategy can be changed without editing a repository or Pi configuration.
