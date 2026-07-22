# Providers

A REPI provider is a user-defined runtime ID that binds models, authentication,
request metadata, and a protocol adapter. REPI starts with no provider or model
catalog. Provider names are not vendor presets, and no provider ID causes REPI
to import a model list automatically.

Every active provider comes from one explicit source:

1. A complete `REPI_*` environment-only model configuration.
2. A provider entry in `~/.repi/agent/models.json`.
3. An extension that explicitly registers a provider implementation.

Protocol adapters are reusable wire implementations. They do not create
providers or models by themselves.

## Table of Contents

- [Provider Identity](#provider-identity)
- [Environment Provider](#environment-provider)
- [models.json Provider](#modelsjson-provider)
- [Extension Provider](#extension-provider)
- [Authentication](#authentication)
- [Protocol Adapters](#protocol-adapters)
- [Operational Commands](#operational-commands)

## Provider Identity

Choose any stable non-empty provider ID, for example `gateway`, `lab-local`, or
`team-proxy`. The same exact ID is used by:

- `REPI_PROVIDER`
- the key under `models.json.providers`
- `--provider <id>` and `repi model ... --provider <id>`
- an `auth.json` credential entry
- `pi.registerProvider("<id>", ...)` in an extension

The ID is runtime data. REPI does not infer endpoint, auth, compatibility, or
models from it. Keep IDs unique across configuration sources unless an extension
intentionally owns the composition of those sources.

## Environment Provider

The environment-only provider is the shortest configuration path:

```bash
export REPI_AUTH_TOKEN="sk-xxxxx"
export REPI_BASE_URL="https://gateway.example/v1"
export REPI_PROVIDER="gateway"             # optional; default: repi-env
export REPI_PROVIDER_NAME="Gateway"        # optional display name
export REPI_MODEL="vendor/model-id"
export REPI_MODEL_API="openai-compatible"

repi --provider gateway --model vendor/model-id
```

`REPI_BASE_URL` and `REPI_MODEL` are required. A partial environment model
configuration is an error and never falls back to a saved or default provider.
`REPI_AUTH_TOKEN` can be replaced by `REPI_API_KEY`, `REPI_MODEL_API_KEY`,
`REPI_TOKEN`, or `REPI_MODEL_TOKEN`. See [models.md](models.md) for the complete
environment variable matrix, validation rules, headers, compatibility controls,
context limits, and pricing metadata.

The environment provider declares only `REPI_MODEL` and the optional
`REPI_SUBAGENT_MODEL`. It never queries an endpoint for more models.

## models.json Provider

Use `~/.repi/agent/models.json` when a provider should persist across shells,
expose multiple explicit models, or carry detailed headers, compatibility, and
pricing metadata:

```json
{
  "providers": {
    "gateway": {
      "name": "Gateway",
      "baseUrl": "https://gateway.example/v1",
      "api": "openai-completions",
      "apiKey": "$GATEWAY_API_KEY",
      "authHeader": false,
      "headers": {
        "X-Tenant": "$TENANT_ID"
      },
      "compat": {
        "supportsDeveloperRole": false,
        "supportsReasoningEffort": false
      },
      "models": [
        {
          "id": "vendor/model-id",
          "name": "Vendor model",
          "input": ["text", "image"],
          "contextWindow": 262144,
          "maxTokens": 16384
        }
      ]
    }
  }
}
```

`models` is the complete explicit list supplied by this file. An omitted or
empty list contributes no selectable models. REPI does not preserve, merge, or
refresh a hidden provider catalog. Provider/model fields and compatibility
schemas are documented in [models.md](models.md).

## Extension Provider

Extensions can register a provider when the transport, model refresh, or auth
flow cannot be expressed by `models.json`:

```typescript
pi.registerProvider("internal", {
  name: "Internal provider",
  baseUrl: "https://internal.example/v1",
  api: "openai-completions",
  apiKey: "$INTERNAL_API_KEY",
  models: [
    {
      id: "team/model-id",
      name: "Team model",
      reasoning: false,
      input: ["text"],
      cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
      contextWindow: 128000,
      maxTokens: 16384
    }
  ]
});
```

An extension may also provide custom stream functions, explicit model refresh,
or an explicit OAuth implementation. OAuth is an extension-owned capability;
there is no default subscription-provider list. See
[custom-provider.md](custom-provider.md) for the extension API.

## Authentication

Authentication is attached to the provider ID explicitly. Supported sources are:

- `REPI_AUTH_TOKEN` (or its aliases) for the environment-only provider.
- `apiKey` in `models.json`, usually an environment reference such as
  `$GATEWAY_API_KEY` or a command such as `!op read ...`.
- Provider or model `headers` in `models.json`, including custom gateway auth
  headers. Header values support environment references and commands; `null`
  suppresses a same-name inherited/default header.
- A stored API key in `~/.repi/agent/auth.json`, created by an explicit login.
- A runtime `--api-key` or an extension-owned authentication flow.

There is no provider-name-to-environment-variable lookup table. Setting a vendor
variable alone does not create a provider. Reference it from `models.json` or
use the environment-only `REPI_*` configuration.

### Explicit login

Create a provider first, then store its credential under the same ID:

```bash
printf '%s' "$GATEWAY_API_KEY" | repi model login --provider gateway --api-key-stdin
repi model list --provider gateway
```

The resulting shape in `~/.repi/agent/auth.json` is provider-ID keyed:

```json
{
  "gateway": {
    "type": "api_key",
    "key": "$GATEWAY_API_KEY"
  }
}
```

Use the login command instead of manually writing this file. REPI creates the
file with user-only permissions and updates it atomically. In interactive mode,
`/logout` removes only the selected provider credential:

```bash
repi
# then enter: /logout
```

### API key and headers

The selected protocol adapter normally translates the resolved `apiKey` into
its standard authentication field. For a generic gateway that specifically
requires a Bearer header, set `authHeader: true` to add:

```text
Authorization: Bearer <resolved apiKey>
```

For non-standard schemes, set an explicit header instead:

```json
{
  "apiKey": "$GATEWAY_API_KEY",
  "headers": {
    "X-API-Key": "$GATEWAY_API_KEY",
    "X-Tenant": "$TENANT_ID"
  }
}
```

Do not commit literal credentials. `apiKey` and header values support
`$ENV_VAR`, `${ENV_VAR}`, request-time `!command`, `$$` for a literal dollar,
and `$!` for a literal leading exclamation mark. Availability checks do not run
secret commands.

## Protocol Adapters

The default distribution registers wire adapters, not provider presets:

| Adapter ID | Protocol |
|---|---|
| `openai-completions` | OpenAI Chat Completions |
| `openai-responses` | OpenAI Responses |
| `anthropic-messages` | Anthropic Messages |
| `google-generative-ai` | Google Generative AI |
| `google-vertex` | Google Vertex AI |
| `azure-openai-responses` | Azure OpenAI Responses |
| `openai-codex-responses` | OpenAI Codex Responses |
| `mistral-conversations` | Mistral Conversations |
| `bedrock-converse-stream` | Amazon Bedrock Converse streaming |

Using an adapter ID still requires an explicit provider, endpoint, model ID, and
compatible authentication. Extensions may register additional adapters. REPI
does not switch between Chat Completions, Responses, and Anthropic Messages when
an endpoint fails; configure the wire protocol the endpoint actually serves.

## Operational Commands

Inspect provider configuration without making a model request:

```bash
repi model doctor
repi model list --provider <provider-id>
repi --offline --list-models
repi --offline --list-models <provider-id>
```

Store or remove an explicit credential:

```bash
repi model login --provider <provider-id> --api-key-stdin
repi                    # then use /logout and select <provider-id>
```

Verify the configured transport with a minimal request:

```bash
repi model test --provider <provider-id> --model <model-id>
repi --provider <provider-id> --model <model-id> --thinking off --no-tools --no-session -p "Reply exactly: PROVIDER_OK"
```

Configuration or authentication errors are reported for the explicit provider
ID. They do not trigger a fallback to an undeclared provider or model.
