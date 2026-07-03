# REPI 运行时配置速查

marker: `model_provider_configuration_runtime`

这份文档给两类读者用：

1. 使用者：直接照着配置模型、网关、本地推理和 compact。
2. REPI 自身：当用户在 `repi` 里问“怎么配置模型/compact”时，应按这里的路径和命令回答，而不是让用户自己猜。

## 1. 配置文件位置

REPI 是独立产品，不读写原版 `pi` 的默认 profile。

| 用途 | 路径 |
|---|---|
| 自定义 provider / model | `~/.repi/agent/models.json` |
| compact、运行偏好、legacy 默认值 | `~/.repi/agent/settings.json` |
| OAuth / API key 登录态 | `~/.repi/agent/auth.json` |
| 逆向/渗透 evidence、memory、mission | `~/.repi/agent/recon/` |

只有显式执行旧登录态导入时，才会从 `~/.pi/agent` 做一次单向复制；正常配置不要改 `~/.pi/agent`。

## 2. 默认模型：Claude Code 风格的 REPI 环境变量

REPI 默认不再依赖写入 `defaultProvider/defaultModel`，优先学习 Claude Code 的“一个 shell 环境即可切换供应商/模型”方式；区别是 REPI 支持 OpenAI-compatible、OpenAI Responses 和 Anthropic Messages 多种 wire format。
REPI 启动器默认设置 `REPI_LOAD_BUILTIN_MODELS=0`，不会把 upstream pi 的大内置 provider/model catalog 自动暴露出来；你显式设置的 `REPI_*` env-only provider 和 `models.json` provider 才是默认运行面。确实需要兼容旧 pi 内置模型表时，可临时设 `REPI_LOAD_BUILTIN_MODELS=1`。

```bash
export REPI_AUTH_TOKEN=sk-xxxxx
export REPI_BASE_URL=https://api.example.com/v1
export REPI_MODEL=provider/model-id
export REPI_MODEL_API=openai-compatible   # aliases: openai-completions, openai-responses, response, anthropic
export REPI_CONTEXT_WINDOW=128000
# Claude Code-style alias also accepted:
# export REPI_AUTO_COMPACT_WINDOW=128000
export REPI_MAX_TOKENS=16384
export REPI_SUBAGENT_MODEL=provider/smaller-or-worker-model

IS_SANDBOX=1 repi --approve --thinking off -p "Reply exactly: REPI_OK"
```

常见别名：

- `REPI_MODEL_API=openai-compatible` / `openai-completions` → Chat Completions wire format。
- `REPI_MODEL_API=openai-responses` / `response` → OpenAI Responses wire format。
- `REPI_MODEL_API=anthropic` / `anthropic-messages` → Anthropic Messages wire format。

## 3. 可选：写入 models.json 的 provider

只有需要长期保存多个 provider、成本字段、headers 或复杂 compat 时才写 `models.json`。适用于大多数商业网关、本地 vLLM/SGLang/LM Studio/Ollama OpenAI shim。

```bash
repi model add \
  --provider openai-compatible \
  --api openai-completions \
  --base-url https://api.example.com/v1 \
  --model provider/model-id \
  --context-window 128000 \
  --max-tokens 16384

repi model login --provider openai-compatible --api-key-stdin
repi model test --provider openai-compatible --model provider/model-id
```

也可以手动写入 `~/.repi/agent/models.json`：

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
          "id": "provider/model-id",
          "name": "Provider Model",
          "input": ["text"],
          "contextWindow": 128000,
          "maxTokens": 16384
        }
      ]
    }
  }
}
```

如果没有使用 `repi model login`，就设置密钥环境变量：

```bash
export OPENAI_COMPAT_API_KEY=<your-token>
```

验证解析，不调用真实模型：

```bash
repi model doctor
repi --offline --list-models
repi --offline --list-models openai-compatible
repi --offline --list-models provider/model-id
```

真实调用时使用：

```bash
repi --provider openai-compatible --model provider/model-id --thinking off --no-tools --no-session -p "Reply exactly: PROVIDER_OK"
```

费用估算：

```bash
repi model cost --provider openai-compatible --model provider/model-id --input-tokens 100000 --output-tokens 10000 --cache-read-tokens 50000
```

费用字段写在 `models[].cost.input/output/cacheRead/cacheWrite`，单位是美元 / 百万 tokens；不需要展示费用时填 `0`。

OpenAI Responses-compatible provider 使用 `api: "openai-responses"`，运行时必须能接收 `POST /v1/responses`。如果 smoke 显示 `/v1/responses` 404，而 `/v1/chat/completions` 可用，就说明该网关当前按 Chat Completions 暴露，应改用 `api: "openai-completions"`，不要依赖自动降级。

### 判断网关格式

不确定网关到底支持 OpenAI Chat Completions、OpenAI Responses 还是 Anthropic Messages 时，按下面顺序处理：

1. 先用最常见的 `openai-completions` 写入配置。
2. 运行 `repi model doctor` 做离线解析验证。
3. 运行 `repi model test --provider <id> --model <model-id>` 做最小真实调用。
4. 如果返回 `/v1/chat/completions` 不存在，但上游文档要求 `/v1/responses`，把 provider 改成 `openai-responses`。
5. 如果服务只暴露 Anthropic Messages，把 provider 改成 `anthropic-messages`，`baseUrl` 填服务根地址。

示例：

```bash
repi model add \
  --provider openai-compatible \
  --api openai-completions \
  --base-url https://api.example.com/v1 \
  --model provider/model-id \
  --context-window 128000 \
  --max-tokens 16384 \
  --set-default

printf '%s' "$API_KEY" | repi model login --provider openai-compatible --api-key-stdin
repi model doctor
repi model test --provider openai-compatible --model provider/model-id
```

## 4. Anthropic-compatible provider

```json
{
  "providers": {
    "anthropic-compatible": {
      "baseUrl": "https://api.anthropic.com",
      "api": "anthropic-messages",
      "apiKey": "$ANTHROPIC_API_KEY",
      "models": [
        {
          "id": "claude-sonnet-4-5",
          "name": "Claude Sonnet",
          "input": ["text", "image"],
          "contextWindow": 200000,
          "maxTokens": 8192
        }
      ]
    }
  }
}
```

如果某个网关虽然转发 Anthropic 模型，但接口是 `/v1/chat/completions`，仍然优先按 `openai-completions` 配。

## 5. 临时覆盖模型

默认推荐使用 `REPI_*` 环境变量。临时覆盖仍可用 CLI 参数：

```bash
repi --provider openai-compatible --model provider/model-id
```

`settings.json` 里的 `defaultProvider/defaultModel` 只作为 legacy/user-explicit fallback；新配置不要依赖它，`repi model doctor --fix` 也不会再自动挑一个 provider 写成默认值。

## 6. auto compact

REPI 默认使用百分比阈值 + reserve token 双保护：

```json
{
  "compaction": {
    "enabled": true,
    "triggerPercent": 85,
    "warningPercent": 80,
    "reserveTokens": 16384,
    "keepRecentTokens": 36000
  }
}
```

实际触发阈值：

```text
min(contextWindow * triggerPercent / 100, contextWindow - reserveTokens)
```

例子：

| contextWindow | 85% | reserve 阈值 | 实际触发 |
|---:|---:|---:|---:|
| 128k | 108.8k | 111.6k | 108.8k |
| 200k | 170k | 183.6k | 170k |
| 32k | 27.2k | 15.6k | 15.6k |

如果上下文贵或任务很长，可以把 `triggerPercent` 改成 `80`；如果模型输出很长，增大 `reserveTokens`。

触发时机：

- provider 支持服务端 `context_management` / compaction 时，服务端可以在一次生成内部先 compact 再继续生成；这是唯一能做到“真正 mid-stream / mid-response 续跑”的方式。
- 对 OpenAI-compatible / Anthropic-compatible 网关等普通流式接口，客户端不能在模型已经开始输出后改写这次请求的上下文。REPI 会在安全边界触发：每个 assistant turn + tool results 结束后、下一次 LLM 请求前；如果没有工具循环，则在当前回复结束后立即 compact。
- 因此 footer 显示超过 `auto@85%` 时，若模型正在持续吐 token，不会强行中断当前 stream；一旦当前 turn 结束，REPI 会自动写 context pack、执行 compact/resume，再继续后续 autonomous loop。


## 7. 非交互长任务稳定性

`repi -p` / `repi --mode text` 默认启用长任务 guardrails，避免模型工具循环、慢 provider、stdin 未关闭或 bash 无超时导致“看起来卡死”。这些输出走 stderr，不污染最终 stdout。

| 变量 | 默认值 | 作用 |
|---|---:|---|
| `REPI_PRINT_PROGRESS` | `1` | 非交互 text 模式输出 `prompt_start`、tool start/end、compaction、retry 和 heartbeat。 |
| `REPI_PRINT_TIMEOUT_MS` | `210000` | 单个 prompt 的 wall timeout，超时后 abort 当前 agent run。 |
| `REPI_PRINT_MAX_TURNS` | `24` | 单个 prompt 的 turn 上限，防止无限 tool loop。 |
| `REPI_PRINT_MAX_TOOL_CALLS` | `80` | 单个 prompt 的 tool call 总量上限。 |
| `REPI_BASH_DEFAULT_TIMEOUT_SECONDS` | `120` | 模型调用 bash 但未显式传 `timeout` 时的默认超时。 |
| `REPI_STDIN_READ_TIMEOUT_MS` | `1500` | 非 TTY stdin 未关闭时的读取保护。 |
| `REPI_READ_STDIN_WITH_PROMPT` | unset | 设为 `1` 时，允许把 stdin 与显式 `-p`/message prompt 拼接。 |

示例：

```bash
REPI_PRINT_TIMEOUT_MS=300000 REPI_PRINT_MAX_TOOL_CALLS=120 repi -p "长任务"
REPI_BASH_DEFAULT_TIMEOUT_SECONDS=30 repi --tools bash -p "跑一个有边界的本地检查"
```

Provider stream idle timeout 使用同一套 provider timeout：`settings.retry.provider.timeoutMs` 或 HTTP idle timeout 设置；OpenAI Codex Responses SSE fallback 和 Anthropic-compatible SSE body read 都会在 idle 超时后取消 reader。

## 8. 常见故障

| 现象 | 处理 |
|---|---|
| `No models match pattern` | 确认 `models.json` 里的 provider id 和 model id 与命令完全一致。 |
| `No API key found` | 确认 `apiKey` 引用的环境变量已 export，或用 `/login <provider>` 配置内置 OAuth provider。 |
| 上游不认识 `developer` role | 在 provider `compat` 里设置 `"supportsDeveloperRole": false`。 |
| 上游不认识 `reasoning_effort` | 设置 `"supportsReasoningEffort": false`。 |
| 上游不认识 `store` 或 tools strict | 设置 `"supportsStore": false`、`"supportsStrictMode": false`。 |
| 本地模型无 usage | 设置 `"supportsUsageInStreaming": false`，并确认 `contextWindow` 手动填对。 |

不要把真实 API key、GitHub token 或私有 endpoint 写入 README、示例或提交历史。
