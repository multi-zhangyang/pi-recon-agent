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

写入 `~/.repi/agent/models.json`：

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

设置密钥：

```bash
export OPENAI_COMPAT_API_KEY=<your-token>
```

验证解析，不调用真实模型：

```bash
repi --list-models
repi --offline \
  --provider openai-compatible \
  --model provider/model-id \
  --thinking off \
  --no-tools \
  --no-session \
  -p "Reply exactly: PROVIDER_OK"
```

真实调用时去掉 `--offline`。

### 可选远程 provider 长跑回归

REPI 的默认 CI 不要求真实密钥；需要验证某个真实网关/模型时，用 opt-in live gate：

```bash
export REPI_REMOTE_PROVIDER_LIVE=1
export REPI_REMOTE_PROVIDER_API=openai-completions
export REPI_REMOTE_PROVIDER_BASE_URL=https://api.example.com/v1
export REPI_REMOTE_PROVIDER_MODEL=provider/model-id
export REPI_REMOTE_PROVIDER_API_KEY_ENV=REPI_REMOTE_PROVIDER_API_KEY
export REPI_REMOTE_PROVIDER_API_KEY=<your-token>

npm run gate:remote-provider-longrun -- --live --no-write
```

Anthropic-compatible endpoint 把 `REPI_REMOTE_PROVIDER_API` 改成 `anthropic-messages`，`REPI_REMOTE_PROVIDER_BASE_URL` 填服务根地址。gate 会临时写 isolated `~/.repi/agent/models.json`，只保存 `$REPI_REMOTE_PROVIDER_API_KEY` 这种环境变量引用；输出 artifact 只保存 hash 和脱敏状态，不保存明文 key。

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

在 `~/.repi/agent/settings.json` 里写：

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

## 6. 常见故障

| 现象 | 处理 |
|---|---|
| `No models match pattern` | 确认 `models.json` 里的 provider id 和 model id 与命令完全一致。 |
| `No API key found` | 确认 `apiKey` 引用的环境变量已 export，或用 `/login <provider>` 配置内置 OAuth provider。 |
| 上游不认识 `developer` role | 在 provider `compat` 里设置 `"supportsDeveloperRole": false`。 |
| 上游不认识 `reasoning_effort` | 设置 `"supportsReasoningEffort": false`。 |
| 上游不认识 `store` 或 tools strict | 设置 `"supportsStore": false`、`"supportsStrictMode": false`。 |
| 本地模型无 usage | 设置 `"supportsUsageInStreaming": false`，并确认 `contextWindow` 手动填对。 |

不要把真实 API key、GitHub token 或私有 endpoint 写入 README、示例或提交历史。
