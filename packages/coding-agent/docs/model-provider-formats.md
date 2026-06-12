# REPI model provider formats

Use `~/.repi/agent/models.json` for custom providers. The important field is `api`, because it controls request serialization.

| Upstream shape | `api` value | Typical `baseUrl` |
|---|---|---|
| OpenAI Chat Completions compatible | `openai-completions` | `https://host/v1` |
| OpenAI Responses compatible | `openai-responses` | `https://host/v1` |
| Anthropic Messages compatible | `anthropic-messages` | `https://host` |
| Google Generative AI | `google-generative-ai` | `https://generativelanguage.googleapis.com/v1beta` |
| Azure OpenAI | built-in provider or compatible gateway | Azure endpoint |
| Amazon Bedrock | built-in provider | AWS SDK/env |
| Google Vertex | built-in provider | ADC/service-account |
| Cloudflare / Vercel / OpenRouter gateways | usually `openai-completions` | gateway `/v1` endpoint |
| vLLM / SGLang / LM Studio / Ollama | `openai-completions` | local `/v1` endpoint |

Recommended credential style:

```text
"apiKey": "$OPENAI_COMPAT_API_KEY"
```

Do not commit real API keys, GitHub tokens, or private endpoints.
