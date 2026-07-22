# Model Provider Formats

REPI has no default provider or model catalog. A provider ID is an arbitrary
runtime key; it does not select a vendor preset. Configure models through a
complete `REPI_*` environment definition, `~/.repi/agent/models.json`, or an
extension.

Use this page to choose a wire adapter. See [models.md](models.md) for the full
environment-variable matrix, model/provider schema, headers, compatibility,
thinking maps, context/output limits, and four-rate pricing with tiers. See
[providers.md](providers.md) for authentication and extension composition.

## Adapter Selection

| Upstream request format | `api` | Typical base URL shape |
|---|---|---|
| OpenAI Chat Completions compatible | `openai-completions` | `https://host/v1` |
| OpenAI Responses compatible | `openai-responses` | `https://host/v1` |
| Anthropic Messages compatible | `anthropic-messages` | `https://host` |
| Google Generative AI | `google-generative-ai` | Explicit endpoint |
| Google Vertex AI | `google-vertex` | Explicit endpoint and auth context |
| Azure OpenAI Responses | `azure-openai-responses` | Explicit endpoint |
| OpenAI Codex Responses | `openai-codex-responses` | Explicit endpoint and auth flow |
| Mistral Conversations | `mistral-conversations` | Explicit endpoint |
| Amazon Bedrock Converse | `bedrock-converse-stream` | Explicit runtime/auth configuration |

These are protocol adapters, not providers. If a gateway exposes
`/v1/chat/completions`, use `openai-completions` regardless of its brand. If it
exposes `/v1/responses` or `/v1/messages`, select the corresponding adapter.

## Environment Model

The shortest explicit configuration is:

```bash
export REPI_AUTH_TOKEN="..."
export REPI_BASE_URL="https://gateway.example/v1"
export REPI_PROVIDER="gateway"             # optional; default: repi-env
export REPI_MODEL="vendor/model-id"
export REPI_MODEL_API="openai-compatible"
export REPI_CONTEXT_WINDOW=262144
export REPI_MAX_TOKENS=16384
export REPI_MODEL_COST_INPUT=0.20
export REPI_MODEL_COST_OUTPUT=0.80
export REPI_MODEL_COST_CACHE_READ=0.02
export REPI_MODEL_COST_CACHE_WRITE=0.25

repi --thinking off -p "Reply exactly: REPI_OK"
```

`REPI_MODEL_API` accepts `openai-compatible`, `openai-responses`, or
`anthropic`, plus the aliases documented in [models.md](models.md). A partial
environment definition is an error; REPI does not fall back to an implicit
provider.

## models.json

Use `~/.repi/agent/models.json` for multiple models or detailed metadata:

```json
{
  "providers": {
    "gateway": {
      "name": "Gateway",
      "baseUrl": "https://gateway.example/v1",
      "api": "openai-completions",
      "apiKey": "$GATEWAY_API_KEY",
      "compat": {
        "supportsDeveloperRole": false,
        "supportsReasoningEffort": false,
        "maxTokensField": "max_tokens"
      },
      "models": [
        {
          "id": "vendor/model-id",
          "name": "Vendor model",
          "reasoning": true,
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
          }
        }
      ]
    }
  }
}
```

Prices are USD per million tokens. `models` is the complete explicit list; it
is never populated from `/models` or a package catalog. Header values may be
strings or `null`, and model-level headers/compatibility override provider
values.

## Verification

```bash
repi model doctor
repi --offline --list-models
repi --offline --list-models gateway
repi model test --provider gateway --model vendor/model-id
```

Start with parse-only checks, then run one minimal real request. Do not infer
capabilities, context limits, or prices from a model name; configure them from
the endpoint's current contract.
