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
| 默认 provider/model、compact、运行偏好 | `~/.repi/agent/settings.json` |
| OAuth / API key 登录态 | `~/.repi/agent/auth.json` |
| 逆向/渗透 evidence、memory、mission | `~/.repi/agent/recon/` |

只有显式执行旧登录态导入时，才会从 `~/.pi/agent` 做一次单向复制；正常配置不要改 `~/.pi/agent`。

## 2. 最小 OpenAI-compatible provider

适用于大多数商业网关、本地 vLLM/SGLang/LM Studio/Ollama OpenAI shim。

推荐用命令写入：

```bash
repi model add \
  --provider openai-compatible \
  --api openai-completions \
  --base-url https://api.example.com/v1 \
  --model provider/model-id \
  --context-window 128000 \
  --max-tokens 16384 \
  --set-default

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

### 自动诊断网关格式

不确定网关到底支持 OpenAI Chat Completions、OpenAI Responses 还是 Anthropic Messages 时，先让 REPI 诊断 endpoint：

```bash
export REPI_PROVIDER_DOCTOR_API_KEY=<your-token>
repi provider-doctor \
  --base-url https://api.example.com/v1 \
  --model provider/model-id \
  --api auto
```

`provider-doctor` 会输出 `ProviderEndpointDoctorV1` 诊断结果和可复制到 `~/.repi/agent/models.json` 的 template。密钥只从 `--api-key-env` 指定的环境变量读取，template 只写 `$REPI_PROVIDER_DOCTOR_API_KEY`，不会写明文 key。若 `openai-responses` 探测结果是 `endpoint_not_found`，应优先按通过的 `openai-completions` 或 `anthropic-messages` 配；需要机器可读输出时加 `--json`。

### 可选远程 provider 长跑回归

REPI 的默认 CI 不要求真实密钥；需要验证某个真实网关/模型时，用 opt-in live gate：

```bash
export REPI_REMOTE_PROVIDER_LIVE=1
export REPI_REMOTE_PROVIDER_API=openai-completions   # 也可用 openai-responses / anthropic-messages
export REPI_REMOTE_PROVIDER_BASE_URL=https://api.example.com/v1
export REPI_REMOTE_PROVIDER_MODEL=provider/model-id
export REPI_REMOTE_PROVIDER_API_KEY_ENV=REPI_REMOTE_PROVIDER_API_KEY
export REPI_REMOTE_PROVIDER_API_KEY=<your-token>

npm run gate:remote-provider-longrun -- --live --no-write
```

OpenAI Responses-compatible endpoint 把 `REPI_REMOTE_PROVIDER_API` 改成 `openai-responses`，并确认 endpoint 支持 `POST /v1/responses`；Anthropic-compatible endpoint 把 `REPI_REMOTE_PROVIDER_API` 改成 `anthropic-messages`，`REPI_REMOTE_PROVIDER_BASE_URL` 填服务根地址。gate 会临时写 isolated `~/.repi/agent/models.json`，只保存 `$REPI_REMOTE_PROVIDER_API_KEY` 这种环境变量引用；输出 artifact 只保存 hash 和脱敏状态，不保存明文 key。

## 3. Anthropic-compatible provider

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

## 4. 默认模型

推荐命令：

```bash
repi model default --provider openai-compatible --model provider/model-id
```

也可以在 `~/.repi/agent/settings.json` 里写：

```json
{
  "defaultProvider": "openai-compatible",
  "defaultModel": "provider/model-id",
  "defaultThinkingLevel": "high"
}
```

也可以每次启动临时指定：

```bash
repi --provider openai-compatible --model provider/model-id
```

## 5. auto compact

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


## 6. 非交互长任务稳定性

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

## 7. 常见故障

| 现象 | 处理 |
|---|---|
| `No models match pattern` | 确认 `models.json` 里的 provider id 和 model id 与命令完全一致。 |
| `No API key found` | 确认 `apiKey` 引用的环境变量已 export，或用 `/login <provider>` 配置内置 OAuth provider。 |
| 上游不认识 `developer` role | 在 provider `compat` 里设置 `"supportsDeveloperRole": false`。 |
| 上游不认识 `reasoning_effort` | 设置 `"supportsReasoningEffort": false`。 |
| 上游不认识 `store` 或 tools strict | 设置 `"supportsStore": false`、`"supportsStrictMode": false`。 |
| 本地模型无 usage | 设置 `"supportsUsageInStreaming": false`，并确认 `contextWindow` 手动填对。 |

不要把真实 API key、GitHub token 或私有 endpoint 写入 README、示例或提交历史。
