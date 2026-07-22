# Models

REPI starts with an empty provider and model catalog. It ships protocol adapters,
not a list of provider presets or model IDs. Every model that can be selected
must be declared explicitly by one of these sources:

1. A complete `REPI_*` environment configuration (the environment-only provider).
2. `~/.repi/agent/models.json` (user-defined providers and models).
3. An extension that explicitly registers a provider or model.

REPI does not discover models from an endpoint, infer a provider from a model
name, load an upstream catalog, or silently add models to a provider. A provider
entry without an explicit model list contributes no selectable models.

## Table of Contents

- [Environment-only Model](#environment-only-model)
- [models.json](#modelsjson)
- [Value Resolution](#value-resolution)
- [Provider Fields](#provider-fields)
- [Model Fields](#model-fields)
- [Pricing](#pricing)
- [Thinking Levels](#thinking-levels)
- [Supported APIs](#supported-apis)
- [Compatibility](#compatibility)
- [Validation and Diagnostics](#validation-and-diagnostics)

## Environment-only Model

Set a base URL and model ID to create one explicit provider without writing a
catalog file. The preferred setup is:

```bash
export REPI_AUTH_TOKEN="sk-xxxxx"
export REPI_BASE_URL="https://gateway.example/v1"
export REPI_PROVIDER="gateway"             # optional provider ID; default: repi-env
export REPI_PROVIDER_NAME="Gateway"        # optional display name
export REPI_MODEL="vendor/model-id"
export REPI_MODEL_API="openai-compatible"  # openai-compatible|openai-responses|anthropic
export REPI_CONTEXT_WINDOW=262144
export REPI_AUTO_COMPACT_WINDOW=262144      # alias of REPI_CONTEXT_WINDOW
export REPI_MAX_TOKENS=16384
export REPI_MODEL_INPUT="text,image"
export REPI_MODEL_REASONING=true

repi --thinking off -p "Reply exactly: REPI_OK"
```

`REPI_MODEL` (or `REPI_MODEL_ID`) and one of the base URL variables are both
required. If any model-related `REPI_*` variable is present but either required
value is missing, startup reports the incomplete configuration and does not
fall back to a saved or implicit model. The token is normally supplied through
`REPI_AUTH_TOKEN`; the other token aliases below are equivalent.

### Environment variable matrix

When more than one alias in a row is set, the first non-empty variable listed is
used. Empty values are skipped.

| Purpose | Variables (in precedence order) | Format or default |
|---|---|---|
| API key | `REPI_AUTH_TOKEN`, `REPI_API_KEY`, `REPI_MODEL_API_KEY`, `REPI_TOKEN`, `REPI_MODEL_TOKEN` | String; injected as the configured API key |
| Base URL | `REPI_BASE_URL`, `REPI_MODEL_BASE_URL`, `REPI_API_BASE_URL`, `REPI_ENDPOINT`, `REPI_MODEL_ENDPOINT` | Non-empty URL; required |
| Provider ID | `REPI_PROVIDER`, `REPI_MODEL_PROVIDER`, `REPI_PROVIDER_ID` | String; default `repi-env` |
| Provider name | `REPI_PROVIDER_NAME`, `REPI_MODEL_PROVIDER_NAME` | String; default `REPI environment model` |
| Primary model ID | `REPI_MODEL`, `REPI_MODEL_ID` | Non-empty string; required |
| Primary model name | `REPI_MODEL_NAME` | Defaults to the model ID |
| Protocol | `REPI_MODEL_API`, `REPI_API`, `REPI_PROTOCOL`, `REPI_MODEL_PROTOCOL` | Defaults to `openai-completions`; aliases are normalized below |
| Worker model ID | `REPI_SUBAGENT_MODEL` | Optional second explicit model |
| Worker model name | `REPI_SUBAGENT_MODEL_NAME` | Defaults to the worker model ID |
| Input modalities | `REPI_MODEL_INPUT`, `REPI_INPUT`, `REPI_MODEL_INPUT_MODALITIES`, `REPI_INPUT_MODALITIES` | Comma list or JSON array of `text` and/or `image`; default `text` |
| Reasoning | `REPI_MODEL_REASONING`, `REPI_REASONING` | Boolean; default `false` |
| Context | `REPI_CONTEXT_WINDOW`, `REPI_MODEL_CONTEXT_WINDOW`, `REPI_AUTO_COMPACT_WINDOW`, `REPI_MODEL_AUTO_COMPACT_WINDOW`, `REPI_CONTEXT_LENGTH`, `REPI_MODEL_CONTEXT_LENGTH` | Integer `1024..1048576`; default `262144` |
| Output limit | `REPI_MAX_TOKENS`, `REPI_MODEL_MAX_TOKENS`, `REPI_MAX_OUTPUT_TOKENS`, `REPI_MODEL_MAX_OUTPUT_TOKENS`, `REPI_OUTPUT_TOKEN_LIMIT` | Integer `64..131072`; default `16384` |
| Provider headers | `REPI_HEADERS`, `REPI_PROVIDER_HEADERS` | JSON object; values are strings or `null` |
| Model headers | `REPI_MODEL_HEADERS` | JSON object merged over provider headers |
| Provider compatibility | `REPI_COMPAT` | JSON object |
| Model compatibility | `REPI_MODEL_COMPAT` | JSON object merged over provider compatibility |
| Thinking map | `REPI_MODEL_THINKING_LEVEL_MAP`, `REPI_THINKING_LEVEL_MAP` | JSON object; values are strings or `null` |
| Bearer header | `REPI_AUTH_HEADER`, `REPI_MODEL_AUTH_HEADER` | Boolean; default disabled |
| Input price | `REPI_MODEL_COST_INPUT`, `REPI_COST_INPUT`, `REPI_MODEL_INPUT_PRICE`, `REPI_INPUT_PRICE` | Non-negative USD per million tokens; default `0` |
| Output price | `REPI_MODEL_COST_OUTPUT`, `REPI_COST_OUTPUT`, `REPI_MODEL_OUTPUT_PRICE`, `REPI_OUTPUT_PRICE` | Non-negative USD per million tokens; default `0` |
| Cache-read price | `REPI_MODEL_COST_CACHE_READ`, `REPI_COST_CACHE_READ`, `REPI_MODEL_CACHE_READ_PRICE`, `REPI_CACHE_READ_PRICE` | Non-negative USD per million tokens; default `0` |
| Cache-write price | `REPI_MODEL_COST_CACHE_WRITE`, `REPI_COST_CACHE_WRITE`, `REPI_MODEL_CACHE_WRITE_PRICE`, `REPI_CACHE_WRITE_PRICE` | Non-negative USD per million tokens; default `0` |
| Price tiers | `REPI_MODEL_COST_TIERS`, `REPI_COST_TIERS` | JSON array; omitted by default |

Protocol aliases are normalized as follows:

| Accepted environment value | Effective API |
|---|---|
| `openai-compatible`, `openai-chat`, `chat`, `chat-completions`, `openai-completions` | `openai-completions` |
| `response`, `responses`, `openai-response`, `openai-responses` | `openai-responses` |
| `anthropic`, `claude`, `anthropic-compatible`, `anthropic-messages` | `anthropic-messages` |

An unknown protocol value is an error. Environment values are parsed strictly:
booleans accept `1/0`, `true/false`, `yes/no`, `y/n`, and `on/off`; numbers must
be finite and within the documented range; headers, compatibility, thinking
maps, and tiers must be valid JSON of the expected shape. Input can be written
as `text,image` or `["text", "image"]`.

The full environment-only example, including headers, compatibility, thinking,
and pricing metadata, is:

```bash
export REPI_HEADERS='{"X-Tenant":"$TENANT_ID"}'
export REPI_MODEL_HEADERS='{"X-Route":"fast"}'
export REPI_COMPAT='{"supportsDeveloperRole":false,"supportsReasoningEffort":false,"maxTokensField":"max_tokens"}'
export REPI_MODEL_COMPAT='{"supportsStore":false}'
export REPI_MODEL_THINKING_LEVEL_MAP='{"off":"none","low":"low","medium":"medium","high":"high","xhigh":null}'
export REPI_AUTH_HEADER=false
export REPI_MODEL_COST_INPUT=0.20
export REPI_MODEL_COST_OUTPUT=0.80
export REPI_MODEL_COST_CACHE_READ=0.02
export REPI_MODEL_COST_CACHE_WRITE=0.25
export REPI_MODEL_COST_TIERS='[{"inputTokensAbove":200000,"input":0.40,"output":1.20,"cacheRead":0.04,"cacheWrite":0.50}]'
```

## models.json

`models.json` is a user-owned, comments-permitted JSON file at
`~/.repi/agent/models.json`. Its top-level shape is:

```json
{
  "providers": {
    "<provider-id>": {
      "baseUrl": "https://host.example/v1",
      "api": "openai-completions",
      "apiKey": "$MY_API_KEY",
      "models": [
        { "id": "vendor/model-id" }
      ]
    }
  }
}
```

The provider ID is arbitrary runtime data. It is not looked up in a preset
table. `models` is an explicit list: entries are not fetched from `/models`,
and an omitted or empty list is empty. An effective `baseUrl` and `api` must be
available at provider or model level for every model.

A complete provider/model definition can look like this:

```json
{
  "providers": {
    "gateway": {
      "name": "Internal gateway",
      "baseUrl": "https://gateway.example/v1",
      "api": "openai-completions",
      "apiKey": "$GATEWAY_API_KEY",
      "authHeader": false,
      "headers": {
        "X-Tenant": "$TENANT_ID"
      },
      "compat": {
        "supportsDeveloperRole": false,
        "supportsReasoningEffort": false,
        "supportsUsageInStreaming": false,
        "maxTokensField": "max_tokens"
      },
      "models": [
        {
          "id": "vendor/model-id",
          "name": "Vendor model",
          "api": "openai-completions",
          "baseUrl": "https://gateway.example/v1",
          "reasoning": true,
          "thinkingLevelMap": {
            "off": "none",
            "minimal": "low",
            "low": "low",
            "medium": "medium",
            "high": "high",
            "xhigh": null,
            "max": null
          },
          "input": ["text", "image"],
          "contextWindow": 262144,
          "maxTokens": 16384,
          "cost": {
            "input": 0.20,
            "output": 0.80,
            "cacheRead": 0.02,
            "cacheWrite": 0.25,
            "tiers": [
              {
                "inputTokensAbove": 200000,
                "input": 0.40,
                "output": 1.20,
                "cacheRead": 0.04,
                "cacheWrite": 0.50
              }
            ]
          },
          "headers": {
            "X-Model-Route": "fast"
          },
          "compat": {
            "supportsStore": false
          }
        }
      ]
    }
  }
}
```

The file is loaded as one immutable snapshot. Invalid files are rejected as a
whole and report the failing JSON path; no partially parsed provider is exposed.
The runtime reloads the file when model configuration is reloaded (including
opening `/model` in the interactive client).

## Value Resolution

`apiKey` and every `headers` value in `models.json` may be a command, an
environment reference, or a literal:

- A string beginning with `!` runs the complete remainder as a shell command and
  uses trimmed stdout. Commands are resolved at request time. REPI does not add
  implicit TTL, stale-value, or recovery behavior; wrap the command if it needs
  caching or fallback behavior.
- `$ENV_VAR` or `${ENV_VAR}` interpolates an environment variable, including
  inside a larger string. Use `${FOO}_suffix` when the suffix is literal.
- `$$` emits a literal `$`; `$!` emits a literal `!` without command execution.
- Any other string is used literally.

For example:

```json
{
  "apiKey": "$MY_API_KEY",
  "headers": {
    "X-Org": "${ORG_PREFIX}-red",
    "X-Secret": "!security find-generic-password -ws 'gateway'"
  }
}
```

Legacy all-uppercase values such as `MY_API_KEY` are migrated to
`$MY_API_KEY` when configuration is loaded. Availability checks inspect whether
an auth value is configured and do not execute shell commands. Keep secrets in
environment variables or `auth.json` rather than committing literal keys to
`models.json`.

## Provider Fields

The `providers` object maps arbitrary non-empty provider IDs to these fields:

| Field | Type | Description |
|---|---|---|
| `name` | non-empty string | Display name; defaults to the provider ID |
| `baseUrl` | non-empty string | Base endpoint inherited by its models |
| `apiKey` | string | API key value using [value resolution](#value-resolution) |
| `api` | non-empty string | Default registered protocol adapter |
| `headers` | object of `string` or `null` | Provider request headers; `null` suppresses a same-name default |
| `compat` | object | Protocol compatibility defaults; see [Compatibility](#compatibility) |
| `authHeader` | boolean | When `true`, add `Authorization: Bearer <resolved apiKey>` |
| `models` | array | Explicit model definitions; omitted/empty means no models |

Authentication can instead come from an explicit `repi model login` entry in
`~/.repi/agent/auth.json` or a CLI/runtime key. A provider ID in `auth.json`
must match the user-defined ID in `models.json`.

## Model Fields

Each item in `models` has the following fields. `id` is the only required field
in the JSON object; `baseUrl` and `api` are required after provider defaults
are applied.

| Field | Type | Default | Description |
|---|---|---|---|
| `id` | non-empty string | none | Identifier sent to the upstream API |
| `name` | non-empty string | `id` | Display and model-pattern matching label |
| `api` | non-empty string | provider `api` | Protocol adapter for this model |
| `baseUrl` | non-empty string | provider `baseUrl` | Endpoint for this model |
| `reasoning` | boolean | `false` | Whether extended thinking is enabled for the model |
| `thinkingLevelMap` | object | provider/API defaults | Maps REPI thinking levels to provider values |
| `input` | non-empty unique array of `text`/`image` | `["text"]` | Input modalities accepted by the model |
| `contextWindow` | positive integer | `128000` | Context window in tokens |
| `maxTokens` | positive integer | `16384` | Maximum generated tokens |
| `cost` | object | all rates `0` | Four rates and optional [tiers](#pricing), in USD per million tokens |
| `headers` | object of `string` or `null` | none | Model headers merged over provider headers |
| `compat` | object | provider `compat` | Model compatibility values merged over provider values |

Model-level `api`, `baseUrl`, `headers`, and `compat` are explicit per-model
settings. They do not select or import another provider.

## Pricing

`cost` uses USD per one million tokens and has four required rate fields whenever
the object is present:

```json
{
  "cost": {
    "input": 0.20,
    "output": 0.80,
    "cacheRead": 0.02,
    "cacheWrite": 0.25,
    "tiers": [
      {
        "inputTokensAbove": 200000,
        "input": 0.40,
        "output": 1.20,
        "cacheRead": 0.04,
        "cacheWrite": 0.50
      }
    ]
  }
}
```

All four rates are finite non-negative numbers. Each tier also requires all
four rates and a non-negative integer `inputTokensAbove`. For a request, REPI
computes total input usage as `input + cacheRead + cacheWrite`. If that value
strictly exceeds one or more thresholds, the tier with the highest exceeded
threshold supplies all four rates for the whole request. Without `cost`, or with
zero rates, cost display and accounting are zero.

## Thinking Levels

`thinkingLevelMap` keys are `off`, `minimal`, `low`, `medium`, `high`, `xhigh`,
and `max`. Each value is one of:

| Value | Meaning |
|---|---|
| omitted | Use the adapter's default mapping for that level |
| string | Send this provider-specific value |
| `null` | The model does not support the level; hide, skip, or clamp it |

Example:

```json
{
  "id": "reasoning-model",
  "reasoning": true,
  "thinkingLevelMap": {
    "off": null,
    "minimal": null,
    "low": "low",
    "medium": "medium",
    "high": "high",
    "xhigh": "max",
    "max": "max"
  }
}
```

Set `reasoning: false` when the upstream does not support explicit reasoning;
do not infer this capability from the model ID.

## Supported APIs

`api` names a registered protocol adapter. The default distribution currently
provides these adapters; extensions may register additional IDs:

| API | Wire protocol |
|---|---|
| `openai-completions` | OpenAI Chat Completions (`/v1/chat/completions`) |
| `openai-responses` | OpenAI Responses (`/v1/responses`) |
| `anthropic-messages` | Anthropic Messages (`/v1/messages`) |
| `google-generative-ai` | Google Generative AI |
| `google-vertex` | Google Vertex AI |
| `azure-openai-responses` | Azure OpenAI Responses |
| `openai-codex-responses` | OpenAI Codex Responses |
| `mistral-conversations` | Mistral Conversations |
| `bedrock-converse-stream` | Amazon Bedrock Converse streaming |

The table describes adapters only. It is not a provider list and does not add
any model IDs. Use an extension for an adapter that needs a custom credential
flow or request implementation.

## Compatibility

Set `compat` on a provider for defaults and on a model for per-model values.
Model values take precedence; nested routing objects are merged by key. REPI
does not guess compatibility from provider or model names.

### OpenAI Chat Completions

The following fields are supported:

| Field | Values or purpose |
|---|---|
| `supportsStore` | Boolean; include `store` |
| `supportsDeveloperRole` | Boolean; use `developer` instead of `system` |
| `supportsReasoningEffort` | Boolean; accept `reasoning_effort` |
| `supportsUsageInStreaming` | Boolean; send `stream_options.include_usage` |
| `maxTokensField` | `max_completion_tokens` or `max_tokens` |
| `requiresToolResultName` | Boolean; include tool-result `name` |
| `requiresAssistantAfterToolResult` | Boolean; insert an assistant message after tool results |
| `requiresThinkingAsText` | Boolean; serialize thinking as text |
| `requiresReasoningContentOnAssistantMessages` | Boolean; include replayed `reasoning_content` |
| `thinkingFormat` | `openai`, `openrouter`, `together`, `deepseek`, `zai`, `qwen`, `chat-template`, `qwen-chat-template`, `string-thinking`, or `ant-ling` |
| `chatTemplateKwargs` | Record of scalar values or `{ "$var": "thinking.enabled"\|"thinking.effort", "omitWhenOff"?: boolean }` |
| `cacheControlFormat` | `anthropic` to emit Anthropic-style cache markers |
| `openRouterRouting` | OpenRouter routing object described below |
| `vercelGatewayRouting` | `{ "only"?: string[], "order"?: string[] }` |
| `zaiToolStream` | Boolean; ZAI tool-stream behavior |
| `supportsStrictMode` | Boolean; include tool `strict` |
| `sendSessionAffinityHeaders` | Boolean; send session-affinity headers |
| `deferredToolsMode` | `system-message`; inject newly activated tool schemas through a system message |
| `sessionAffinityFormat` | `openai`, `openai-nosession`, or `openrouter` |
| `supportsLongCacheRetention` | Boolean; opt in to long prompt-cache retention |

`openRouterRouting` accepts `allow_fallbacks`, `require_parameters`,
`data_collection` (`deny` or `allow`), `zdr`, `enforce_distillable_text`,
`order`, `only`, `ignore`, `quantizations`, `sort`, `max_price`,
`preferred_min_throughput`, and `preferred_max_latency`. `sort` is a string or
`{ "by"?: string, "partition"?: string|null }`; `max_price` may contain
`prompt`, `completion`, `image`, `audio`, and `request` numbers or strings;
throughput/latency may be a number or `{ "p50"?, "p75"?, "p90"?, "p99"? }`.

### OpenAI Responses

| Field | Values or purpose |
|---|---|
| `supportsStore` | Boolean; include `store` |
| `supportsDeveloperRole` | Boolean; preserve the `developer` role |
| `sendSessionIdHeader` | Boolean; send the session ID header |
| `sessionAffinityFormat` | `openai`, `openai-nosession`, or `openrouter` |
| `supportsLongCacheRetention` | Boolean; opt in to long retention |
| `supportsToolSearch` | Boolean; allow Responses tool search |

### Anthropic Messages

| Field | Values or purpose |
|---|---|
| `supportsEagerToolInputStreaming` | Boolean; accept per-tool `eager_input_streaming` |
| `supportsLongCacheRetention` | Boolean; accept `cache_control.ttl: "1h"` |
| `sendSessionAffinityHeaders` | Boolean; send `x-session-affinity` |
| `supportsCacheControlOnTools` | Boolean; accept cache markers on tools |
| `supportsTemperature` | Boolean; send temperature |
| `forceAdaptiveThinking` | Boolean; send adaptive thinking and effort |
| `supportsToolReferences` | Boolean; accept tool references |
| `allowEmptySignature` | Boolean; replay empty thinking signatures |

### Compatibility examples

For an OpenAI-compatible local server:

```json
{
  "providers": {
    "local": {
      "baseUrl": "http://127.0.0.1:8080/v1",
      "api": "openai-completions",
      "apiKey": "local",
      "compat": {
        "supportsDeveloperRole": false,
        "supportsReasoningEffort": false,
        "supportsUsageInStreaming": false,
        "maxTokensField": "max_tokens"
      },
      "models": [{ "id": "qwen-local" }]
    }
  }
}
```

For an Anthropic-compatible gateway:

```json
{
  "providers": {
    "anthropic-gateway": {
      "baseUrl": "https://gateway.example",
      "api": "anthropic-messages",
      "apiKey": "$ANTHROPIC_GATEWAY_KEY",
      "compat": {
        "supportsEagerToolInputStreaming": false,
        "supportsLongCacheRetention": true,
        "supportsCacheControlOnTools": false,
        "forceAdaptiveThinking": true
      },
      "models": [{ "id": "claude-compatible", "input": ["text", "image"] }]
    }
  }
}
```

## Validation and Diagnostics

`models.json` is checked before it enters the runtime. The top-level
`providers` record, provider/model field types, non-empty IDs, input modality
constraints, positive context/output limits, non-negative pricing, and JSON
compatibility structures are validated. A malformed JSON document or invalid
schema produces a path-specific error and leaves the invalid snapshot unloaded.
Environment-only configuration applies the additional numeric bounds documented
in the environment matrix and rejects invalid protocol, boolean, JSON, or tier
values instead of coercing them.

Use these commands to inspect explicit configuration without contacting a
provider:

```bash
repi model doctor
repi --offline --list-models
repi --offline --list-models <provider-id>
```

After the provider and model are declared, make a minimal request with the
actual endpoint and protocol:

```bash
repi model test --provider <provider-id> --model <model-id>
repi --provider <provider-id> --model <model-id> --thinking off --no-tools --no-session -p "Reply exactly: PROVIDER_OK"
```

If an endpoint returns a 404 for `/v1/responses` but accepts
`/v1/chat/completions`, change the explicit model/provider `api` to
`openai-completions`; REPI does not silently downgrade protocols.
