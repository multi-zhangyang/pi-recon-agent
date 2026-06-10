# Pi-RECON Model Provider Configuration

Pi-RECON 通过 `models.json` 接入不同的模型服务。本文说明 provider 的配置结构、主流 API adapter 的选择方式、常见兼容参数，以及文本响应和工具调用的验证流程。

支持的接入形态包括：

- OpenAI Chat Completions-compatible gateways and local runtimes
- OpenAI Responses-compatible endpoints
- Anthropic Messages-compatible endpoints
- Google Gemini / Generative AI
- Azure OpenAI
- Amazon Bedrock
- Google Vertex AI
- Cloudflare AI Gateway / Workers AI
- Vercel AI Gateway and other routing gateways
- Ollama / vLLM / SGLang / LM Studio

`repi` 的自定义 provider 配置文件是：

```text
~/.repi/agent/models.json
```

默认模型、可切换模型等运行偏好在：

```text
~/.repi/agent/settings.json
```

凭据建议通过环境变量或命令式 secret loader 注入。下面的示例只使用占位符和环境变量引用，例如 `$OPENAI_API_KEY`、`$ANTHROPIC_API_KEY`、`$OPENROUTER_API_KEY`、`$GEMINI_API_KEY`。


## 0. 自定义模型支持结论

支持。REPI 读取独立的 `~/.repi/agent/models.json`，可以配置 OpenAI-compatible、OpenAI Responses-compatible、Anthropic Messages-compatible、Google、Azure、Bedrock、Vertex、Cloudflare/Vercel 网关和本地 vLLM/SGLang/LM Studio/Ollama。每个模型的 `contextWindow` 会被 auto-compact 阈值使用；REPI 默认 `triggerPercent=85`、`warningPercent=80`、`reserveTokens=16384`，可在 `~/.repi/agent/settings.json` 覆盖。

## 1. Provider 配置结构

一个 provider 条目包含四类信息：

1. API 协议：`api`。
2. Endpoint：`baseUrl`。
3. 认证来源：`apiKey` / `headers` / `authHeader`。
4. 上游模型 ID：`models[].id`。

通用骨架：

```json
{
  "providers": {
    "provider-id": {
      "baseUrl": "https://api.example.com/v1",
      "api": "openai-completions",
      "apiKey": "$EXAMPLE_API_KEY",
      "compat": {},
      "models": [
        {
          "id": "vendor/model-id",
          "name": "Human label",
          "reasoning": false,
          "input": ["text"],
          "contextWindow": 128000,
          "maxTokens": 16384,
          "cost": { "input": 0, "output": 0, "cacheRead": 0, "cacheWrite": 0 }
        }
      ]
    }
  }
}
```

字段含义：

| 字段 | 含义 |
|---|---|
| `provider-id` | Pi 本地 provider 名，命令里用 `--provider provider-id`。建议短、稳定、无空格。 |
| `baseUrl` | API endpoint。OpenAI-compatible 通常带 `/v1`；Anthropic-compatible 通常填 host 根路径。 |
| `api` | Pi 发送 payload 的协议/序列化格式，比厂商品牌更重要。 |
| `apiKey` | token 获取方式。推荐环境变量引用，不推荐明文。 |
| `headers` | 额外请求头，例如网关 header、组织 ID、路由 header。 |
| `authHeader` | 为 `true` 时额外发送 `Authorization: Bearer <apiKey>`，常用于 bearer-token Anthropic proxy。 |
| `models[].id` | 原样传给上游 API 的模型 ID。 |
| `compat` | 兼容性开关，用来适配不完整 OpenAI/Anthropic 协议、网关、local runtime。 |

## 2. 主流格式速查表

| 上游形态 | Pi `api` / provider 路径 | 常见 `baseUrl` | 适用场景 |
|---|---|---|---|
| OpenAI Chat Completions compatible | `openai-completions` | `https://host/v1` | 大多数模型网关、OpenRouter、通用 OpenAI-compatible endpoint、vLLM、SGLang、LM Studio、Ollama。 |
| OpenAI Responses compatible | `openai-responses` | `https://host/v1` | Responses API endpoint 或兼容代理。 |
| Anthropic Messages compatible | `anthropic-messages` | `https://host` | Claude/Anthropic `/v1/messages` 兼容网关和代理。 |
| Google Generative AI | `google-generative-ai` | `https://generativelanguage.googleapis.com/v1beta` | Google AI Studio / Gemini direct endpoint。 |
| Azure OpenAI | 内置 `azure-openai-responses` | env 驱动 | Azure deployment 映射，优先用内置 provider。 |
| Amazon Bedrock | 内置 `amazon-bedrock` | AWS SDK/env 驱动 | Bedrock ConverseStream，优先用内置 provider。 |
| Google Vertex | 内置 `google-vertex` | ADC/service account 驱动 | Vertex AI Gemini，优先用内置 provider。 |
| Cloudflare AI Gateway / Workers AI | 内置 provider 或 `openai-completions` | Cloudflare env / gateway endpoint | Cloudflare 统一网关、Workers AI、本地 BYOK/Stored BYOK。 |
| Vercel AI Gateway / 通用路由网关 | 通常 `openai-completions` | `https://ai-gateway.vercel.sh/v1` 或网关地址 | 多上游路由、fallback、provider order。 |

## 3. Credential references

推荐写法：

```json
"apiKey": "$OPENAI_API_KEY"
"apiKey": "$ANTHROPIC_API_KEY"
"apiKey": "${KEY_PREFIX}_${KEY_SUFFIX}"
"apiKey": "!op read op://vault/item/token"
```

不要提交明文凭据：

```json
"apiKey": "sk-真实token"
```

Pi 会在请求时解析环境变量或命令输出，配置文件只保留引用。

## 4. OpenAI Chat Completions-compatible

这是最通用的格式，绝大多数网关和本地服务都优先尝试它。

```json
{
  "providers": {
    "openai-compatible": {
      "baseUrl": "https://api.example.com/v1",
      "api": "openai-completions",
      "apiKey": "$OPENAI_COMPAT_API_KEY",
      "compat": {
        "supportsDeveloperRole": false,
        "supportsReasoningEffort": false,
        "supportsStore": false,
        "supportsStrictMode": false,
        "maxTokensField": "max_tokens"
      },
      "models": [
        {
          "id": "vendor/model-name",
          "name": "Vendor Model Name",
          "reasoning": false,
          "input": ["text"],
          "contextWindow": 128000,
          "maxTokens": 16384,
          "cost": { "input": 0, "output": 0, "cacheRead": 0, "cacheWrite": 0 }
        }
      ]
    }
  }
}
```

适用：

- OpenAI-compatible 商业网关。
- 商业模型网关或厂商 OpenAI-compatible endpoint。
- DeepSeek/ZAI/Qwen 通过 `/v1/chat/completions` 暴露时。
- Groq、Cerebras、Fireworks、Together 等兼容接口。
- vLLM、SGLang、LocalAI、LM Studio、Ollama、text-generation-webui OpenAI shim。

常见兼容性修正：

| 报错/现象 | 先尝试的设置 |
|---|---|
| 上游不认识 `developer` role | `"supportsDeveloperRole": false` |
| 上游不认识 `reasoning_effort` | `"supportsReasoningEffort": false` |
| 上游不认识 `store` | `"supportsStore": false` |
| 上游不认识 tools 里的 `strict` | `"supportsStrictMode": false` |
| 上游要求 `max_tokens` | `"maxTokensField": "max_tokens"` |
| 上游不支持 streaming usage | `"supportsUsageInStreaming": false` |

## 5. OpenRouter / 路由型 OpenAI-compatible

OpenRouter 这类网关仍然通常走 `openai-completions`，模型 ID 里常带上游厂商前缀。

```json
{
  "providers": {
    "openrouter-custom": {
      "baseUrl": "https://openrouter.ai/api/v1",
      "api": "openai-completions",
      "apiKey": "$OPENROUTER_API_KEY",
      "models": [
        {
          "id": "provider/model-id",
          "name": "OpenRouter Routed Model",
          "contextWindow": 262144,
          "maxTokens": 16384,
          "compat": {
            "openRouterRouting": {
              "allow_fallbacks": true,
              "require_parameters": false,
              "data_collection": "deny"
            }
          }
        }
      ]
    }
  }
}
```

如果模型走 Anthropic 上游但网关暴露 OpenAI-compatible payload，优先还是看网关文档要求：如果它收 `/v1/chat/completions`，就配 `openai-completions`；如果它收 `/v1/messages`，才配 `anthropic-messages`。

## 6. 本地 OpenAI-compatible runtime

vLLM / SGLang / LM Studio / LocalAI 等：

```json
{
  "providers": {
    "local-vllm": {
      "baseUrl": "http://127.0.0.1:8000/v1",
      "api": "openai-completions",
      "apiKey": "local",
      "compat": {
        "supportsDeveloperRole": false,
        "supportsReasoningEffort": false,
        "supportsStore": false,
        "supportsStrictMode": false,
        "supportsUsageInStreaming": false,
        "maxTokensField": "max_tokens"
      },
      "models": [
        {
          "id": "Qwen/Qwen3-Coder-30B-A3B-Instruct",
          "name": "Local Qwen Coder",
          "reasoning": true,
          "input": ["text"],
          "contextWindow": 128000,
          "maxTokens": 8192,
          "cost": { "input": 0, "output": 0, "cacheRead": 0, "cacheWrite": 0 }
        }
      ]
    }
  }
}
```

Ollama 常用：

```json
{
  "providers": {
    "ollama": {
      "baseUrl": "http://localhost:11434/v1",
      "api": "openai-completions",
      "apiKey": "ollama",
      "compat": {
        "supportsDeveloperRole": false,
        "supportsReasoningEffort": false,
        "supportsStore": false,
        "supportsStrictMode": false,
        "supportsUsageInStreaming": false,
        "maxTokensField": "max_tokens"
      },
      "models": [
        { "id": "qwen2.5-coder:7b", "name": "Ollama Qwen Coder" }
      ]
    }
  }
}
```

## 7. OpenAI Responses-compatible

如果 endpoint 实现 Responses API，而不是 Chat Completions，用：

```json
{
  "providers": {
    "openai-responses-proxy": {
      "baseUrl": "https://api.example.com/v1",
      "api": "openai-responses",
      "apiKey": "$OPENAI_RESPONSES_API_KEY",
      "compat": {
        "supportsDeveloperRole": true,
        "supportsLongCacheRetention": true
      },
      "models": [
        {
          "id": "gpt-5.1",
          "name": "Responses GPT",
          "reasoning": true,
          "input": ["text", "image"],
          "contextWindow": 400000,
          "maxTokens": 32768,
          "cost": { "input": 0, "output": 0, "cacheRead": 0, "cacheWrite": 0 }
        }
      ]
    }
  }
}
```

官方 OpenAI 通常直接用内置 provider：

```bash
export OPENAI_API_KEY=<token>
./pi-test.sh --provider openai --model gpt-5.4
```

## 8. Anthropic Messages-compatible

适用于接收 Anthropic `/v1/messages` payload 的 endpoint。

```json
{
  "providers": {
    "anthropic-compatible": {
      "baseUrl": "https://api.example.com",
      "api": "anthropic-messages",
      "apiKey": "$ANTHROPIC_COMPAT_API_KEY",
      "compat": {
        "supportsEagerToolInputStreaming": false,
        "supportsLongCacheRetention": false,
        "supportsCacheControlOnTools": false,
        "sendSessionAffinityHeaders": false
      },
      "models": [
        {
          "id": "claude-or-compatible-model",
          "name": "Anthropic Compatible Model",
          "reasoning": false,
          "input": ["text"],
          "contextWindow": 200000,
          "maxTokens": 16384,
          "cost": { "input": 0, "output": 0, "cacheRead": 0, "cacheWrite": 0 }
        }
      ]
    }
  }
}
```

认证细节：

- 原生 Anthropic API key 一般只需要 `apiKey`。
- bearer-token 代理通常需要 `"authHeader": true`，让 Pi 额外发送 `Authorization: Bearer <apiKey>`。
- 如果代理拒绝 Anthropic 工具流式或 cache 字段，就关闭 `supportsEagerToolInputStreaming`、`supportsLongCacheRetention`、`supportsCacheControlOnTools`。

原生 Anthropic 内置 provider：

```bash
export ANTHROPIC_API_KEY=<token>
./pi-test.sh --provider anthropic --model claude-sonnet-4-5
```

Bearer proxy 示例：

```json
{
  "providers": {
    "bearer-anthropic-proxy": {
      "baseUrl": "https://proxy.example.com",
      "api": "anthropic-messages",
      "apiKey": "$ANTHROPIC_COMPAT_API_KEY",
      "authHeader": true,
      "compat": {
        "supportsEagerToolInputStreaming": false,
        "supportsLongCacheRetention": false,
        "supportsCacheControlOnTools": false
      },
      "models": [
        { "id": "gateway/model-id", "name": "Model via Anthropic-compatible proxy" }
      ]
    }
  }
}
```

## 9. Google Gemini / Generative AI

```json
{
  "providers": {
    "google-ai-studio-custom": {
      "baseUrl": "https://generativelanguage.googleapis.com/v1beta",
      "api": "google-generative-ai",
      "apiKey": "$GEMINI_API_KEY",
      "models": [
        {
          "id": "gemini-3.1-pro-preview",
          "name": "Gemini Pro",
          "reasoning": true,
          "input": ["text", "image"],
          "contextWindow": 1048576,
          "maxTokens": 65536,
          "cost": { "input": 0, "output": 0, "cacheRead": 0, "cacheWrite": 0 }
        }
      ]
    }
  }
}
```

内置 Gemini：

```bash
export GEMINI_API_KEY=<token>
./pi-test.sh --provider google --model gemini-3.1-pro-preview
```

Vertex 推荐用内置 provider 和 ADC/service account：

```bash
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json
export GOOGLE_CLOUD_PROJECT=<project>
export GOOGLE_CLOUD_LOCATION=us-central1
./pi-test.sh --provider google-vertex --model gemini-3.1-pro-preview
```

## 10. Azure OpenAI

Azure 优先用内置 `azure-openai-responses`，不要硬伪装成普通 OpenAI-compatible，除非你的网关真的暴露标准 `/v1` OpenAI endpoint。

```bash
export AZURE_OPENAI_API_KEY=<token>
export AZURE_OPENAI_BASE_URL=https://<resource>.openai.azure.com
export AZURE_OPENAI_API_VERSION=2024-02-01
export AZURE_OPENAI_DEPLOYMENT_NAME_MAP=gpt-5.4=my-gpt54-deployment

./pi-test.sh --provider azure-openai-responses --model gpt-5.4
```

## 11. Amazon Bedrock

Bedrock 走 AWS SDK / ConverseStream，不是简单 `apiKey + baseUrl`。优先用内置 provider：

```bash
export AWS_PROFILE=<profile>
export AWS_REGION=us-east-1
./pi-test.sh --provider amazon-bedrock --model us.anthropic.claude-sonnet-4-20250514-v1:0
```

其他认证形态可按环境使用：`AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`、bearer token、ECS credentials、IRSA 等。

## 12. Cloudflare AI Gateway / Workers AI

优先用内置 provider：

```bash
export CLOUDFLARE_API_KEY=<token>
export CLOUDFLARE_ACCOUNT_ID=<account-id>
export CLOUDFLARE_GATEWAY_ID=<gateway-slug>

./pi-test.sh --provider cloudflare-ai-gateway --model workers-ai/@cf/<model-id>
./pi-test.sh --provider cloudflare-workers-ai --model @cf/<model-id>
```

如果只是把 Cloudflare 当作普通 OpenAI-compatible 代理，就按 `openai-completions` 配，并把网关要求的额外 header 写入 `headers`。

## 13. Vercel AI Gateway / 通用路由网关

```json
{
  "providers": {
    "vercel-gateway-custom": {
      "baseUrl": "https://ai-gateway.vercel.sh/v1",
      "api": "openai-completions",
      "apiKey": "$AI_GATEWAY_API_KEY",
      "models": [
        {
          "id": "anthropic/claude-sonnet-4-5",
          "name": "Claude via Gateway",
          "reasoning": true,
          "input": ["text", "image"],
          "compat": {
            "vercelGatewayRouting": {
              "order": ["anthropic", "bedrock"]
            }
          }
        }
      ]
    }
  }
}
```

## 14. Reasoning / thinking 兼容性

不要盲目把所有模型都设置成 `reasoning: true`。如果上游或网关不支持显式 reasoning/thinking 参数，会影响工具调用稳定性。逆向渗透任务里，工具调用、复现命令和证据链通常比暴露厂商 thinking 字段更重要。

保守策略：

```json
"reasoning": false
```

如果上游确实支持 reasoning，再设置：

```json
{
  "reasoning": true,
  "thinkingLevelMap": {
    "off": "none",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "xhigh": null
  },
  "compat": {
    "thinkingFormat": "openrouter"
  }
}
```

当前代码里常见 OpenAI-compatible `thinkingFormat` 值包括：

```text
openai, openrouter, deepseek, together, zai, qwen, qwen-chat-template
```

## 15. 模型选择与 smoke test

列出模型：

```bash
repi --offline --list-models
repi --offline --list-models <provider-or-model>
```

文本 smoke test：

```bash
repi --offline \
  --provider <provider-id> \
  --model <model-id> \
  --thinking off \
  --no-tools \
  --no-session \
  -p "Reply exactly: PROVIDER_OK"
```

工具调用 smoke test：

```bash
repi --offline \
  --provider <provider-id> \
  --model <model-id> \
  --thinking off \
  --tools bash \
  --no-session \
  -p "Use bash to run: printf TOOL_OK. Then answer with the exact observed output."
```

## 16. Pi-RECON provider 验证顺序

新增或变更 provider 后按这个顺序验：

1. 更新 `~/.repi/agent/models.json`，只写 env 引用，不写 token 明文。
2. `repi --offline --list-models <provider-or-model>`。
3. `--no-tools` 文本 smoke test。
4. `--tools bash` 或窄工具 allowlist 的工具调用 smoke test。
5. 小型授权本地靶场验证：路由枚举、工具调用、证据抽取、漏洞证明、最终报告。
6. profile guard：

```bash
npx vitest --run packages/coding-agent/test/recon-profile.test.ts
scripts/reverse-agent/verify-profile.mjs /root/pi-diy/pi
```
