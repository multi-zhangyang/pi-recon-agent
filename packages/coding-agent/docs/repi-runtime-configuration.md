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
| 逆向/渗透 evidence、mission | `~/.repi/agent/recon/` |

只有显式执行旧登录态导入时，才会从 `~/.pi/agent` 做一次单向复制；正常配置不要改 `~/.pi/agent`。

## 2. 模型来源：Claude Code 风格的 REPI 环境变量

REPI 默认不再依赖写入 `defaultProvider/defaultModel`，也不携带或加载 upstream pi 的内置 provider/model catalog。默认 catalog 为空；当前运行面只有显式设置的 `REPI_*` env-only provider、`models.json` provider 和扩展动态注册 provider。

一个 shell 环境即可切换供应商、协议和模型：

```bash
export REPI_AUTH_TOKEN=sk-xxxxx
export REPI_BASE_URL=https://api.example.com/v1
export REPI_PROVIDER=my-provider              # optional; footer/provider id, default: repi-env
export REPI_MODEL=provider/model-id
export REPI_MODEL_API=openai-compatible       # openai-compatible | openai-responses | anthropic
export REPI_CONTEXT_WINDOW=128000
export REPI_AUTO_COMPACT_WINDOW=128000        # alias of REPI_CONTEXT_WINDOW
export REPI_MAX_TOKENS=16384
export REPI_MODEL_INPUT=text,image
export REPI_MODEL_REASONING=true
export REPI_SUBAGENT_MODEL=provider/smaller-or-worker-model

IS_SANDBOX=1 repi --approve --thinking off -p "Reply exactly: REPI_OK"
```

高级元数据也可以只放在环境变量中，不需要生成模型目录：

```bash
export REPI_HEADERS='{"X-Tenant":"$TENANT_ID"}'
export REPI_MODEL_HEADERS='{"X-Model-Route":"fast"}'
export REPI_COMPAT='{"supportsDeveloperRole":false,"supportsReasoningEffort":false,"maxTokensField":"max_tokens"}'
export REPI_MODEL_COMPAT='{"supportsStore":false}'
export REPI_AUTH_HEADER=0
export REPI_MODEL_THINKING_LEVEL_MAP='{"off":"none","low":"low","medium":"medium","high":"high","xhigh":"high"}'
export REPI_MODEL_COST_INPUT=0.20
export REPI_MODEL_COST_OUTPUT=0.80
export REPI_MODEL_COST_CACHE_READ=0.02
export REPI_MODEL_COST_CACHE_WRITE=0.25
export REPI_MODEL_COST_TIERS='[{"inputTokensAbove":200000,"input":0.40,"output":1.20,"cacheRead":0.04,"cacheWrite":0.50}]'
```

环境变量字段：

| 变量 | 格式 / 作用 |
|---|---|
| `REPI_AUTH_TOKEN` | API token；也接受 `REPI_API_KEY`、`REPI_MODEL_API_KEY`。 |
| `REPI_BASE_URL` | provider 根 URL；也接受 `REPI_MODEL_BASE_URL`。 |
| `REPI_PROVIDER` | provider id；也接受 `REPI_MODEL_PROVIDER`、`REPI_PROVIDER_ID`。 |
| `REPI_PROVIDER_NAME` | footer/status 中显示的 provider 名称。 |
| `REPI_MODEL` | 主模型 id；也接受 `REPI_MODEL_ID`。 |
| `REPI_MODEL_NAME` | 主模型显示名称。 |
| `REPI_MODEL_API` | `openai-compatible`、`openai-responses` 或 `anthropic`；也接受 `REPI_API` 及协议别名。 |
| `REPI_CONTEXT_WINDOW` | 正整数上下文上限；也接受 `REPI_MODEL_CONTEXT_WINDOW`。 |
| `REPI_AUTO_COMPACT_WINDOW` | `REPI_CONTEXT_WINDOW` 的 Claude Code 风格别名；也接受 `REPI_MODEL_AUTO_COMPACT_WINDOW`。 |
| `REPI_MAX_TOKENS` | 正整数输出上限；也接受 `REPI_MODEL_MAX_TOKENS`、`REPI_MAX_OUTPUT_TOKENS`。 |
| `REPI_MODEL_INPUT` | 逗号分隔的 `text` / `image`，例如 `text,image`；`REPI_INPUT` 是别名。 |
| `REPI_MODEL_REASONING` | `true/false`（也接受 `1/0`）；`REPI_REASONING` 是别名。 |
| `REPI_MODEL_THINKING_LEVEL_MAP` | JSON map；值是 provider 字符串或 `null`（表示不支持该级别）。 |
| `REPI_HEADERS` / `REPI_MODEL_HEADERS` | JSON request headers；后者用于模型级覆盖，值可引用 `$ENV_VAR`，`null` 会移除 header。 |
| `REPI_COMPAT` / `REPI_MODEL_COMPAT` | JSON wire-compatibility overrides；字段必须符合所选 API。 |
| `REPI_AUTH_HEADER` | 为 `true` 时用 token 补发 `Authorization: Bearer <token>`；默认关闭。 |
| `REPI_MODEL_COST_INPUT` / `REPI_MODEL_COST_OUTPUT` | 输入/输出价格，单位 USD / 1M tokens。 |
| `REPI_MODEL_COST_CACHE_READ` / `REPI_MODEL_COST_CACHE_WRITE` | cache read/write 价格，单位 USD / 1M tokens。 |
| `REPI_MODEL_COST_TIERS` | JSON 数组；每项含 `inputTokensAbove` 与四类价格。也接受 `REPI_COST_*` / `REPI_*_PRICE` 别名。 |

兼容别名按 canonical 名称的顺序解析，首个非空值生效：`REPI_TOKEN` / `REPI_MODEL_TOKEN`、`REPI_API_BASE_URL` / `REPI_ENDPOINT` / `REPI_MODEL_ENDPOINT`、`REPI_PROTOCOL` / `REPI_MODEL_PROTOCOL`、`REPI_CONTEXT_LENGTH` / `REPI_MODEL_CONTEXT_LENGTH`、`REPI_MODEL_MAX_OUTPUT_TOKENS` / `REPI_OUTPUT_TOKEN_LIMIT`、`REPI_MODEL_INPUT_MODALITIES` / `REPI_INPUT_MODALITIES`、`REPI_PROVIDER_HEADERS`、`REPI_THINKING_LEVEL_MAP`、`REPI_MODEL_AUTH_HEADER`，以及各价格字段对应的 `REPI_COST_*`、`REPI_MODEL_*_PRICE`、`REPI_*_PRICE` 和 `REPI_COST_TIERS`。

常见协议别名：

- `openai-compatible` / `openai-completions` / `chat-completions` → Chat Completions。
- `openai-responses` / `response` / `responses` → OpenAI Responses。
- `anthropic` / `anthropic-messages` / `claude` → Anthropic Messages。

一次请求的总输入用量按 `input + cacheRead + cacheWrite` 计算；它超过 tier 的 `inputTokensAbove` 时，选择已超过阈值中最高的一层，并将该层四类价格应用于整次请求。不计费时可省略 cost 字段，或显式填 `0`。所有 header/compat/thinking map 环境值都是 JSON，建议通过 `$ENV_VAR` 引用敏感值。

Base URL 按 SDK 语义填写：

- OpenAI-compatible / Responses：通常是 `https://host/v1`。
- Anthropic Messages：通常是 `https://host`，Anthropic SDK 会自行请求 `/v1/messages`。

## 3. 可选：写入 models.json 的 provider

只有需要长期保存多个 provider、成本字段、headers 或复杂 compat 时才写 `models.json`。适用于大多数商业网关、本地 vLLM/SGLang/LM Studio/Ollama OpenAI shim。

```bash
repi model add \
  --provider gateway \
  --api openai-completions \
  --base-url https://api.example.com/v1 \
  --model provider/model-id \
  --context-window 128000 \
  --max-tokens 16384

repi model login --provider gateway --api-key-stdin
repi model test --provider gateway --model provider/model-id
```

也可以手动写入 `~/.repi/agent/models.json`：

```json
{
  "providers": {
    "gateway": {
      "name": "Gateway",
      "baseUrl": "https://api.example.com/v1",
      "api": "openai-completions",
      "apiKey": "$GATEWAY_API_KEY",
      "authHeader": false,
      "headers": {
        "X-Tenant": "$TENANT_ID"
      },
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
          "reasoning": true,
          "thinkingLevelMap": {
            "off": "none",
            "low": "low",
            "medium": "medium",
            "high": "high",
            "xhigh": null
          },
          "input": ["text", "image"],
          "contextWindow": 262144,
          "maxTokens": 16384,
          "headers": {
            "X-Model-Route": "fast"
          },
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

如果没有使用 `repi model login`，就设置密钥环境变量：

```bash
export GATEWAY_API_KEY=<your-token>
export TENANT_ID=<your-tenant>
```

provider 与 model 都可以设置 `api`、`baseUrl`、`headers`、`compat`；model 字段优先，headers/compat 会按 key 合并。`apiKey` 与 header 字符串支持 `$ENV_VAR` 引用，header 值设为 `null` 可移除同名继承 header。`authHeader: true` 用于必须显式发送 Bearer header 的网关。

验证解析，不调用真实模型：

```bash
repi model doctor
repi --offline --list-models
repi --offline --list-models gateway
repi --offline --list-models provider/model-id
```

真实调用时使用：

```bash
repi --provider gateway --model provider/model-id --thinking off --no-tools --no-session -p "Reply exactly: PROVIDER_OK"
```

费用估算：

```bash
repi model cost --provider gateway --model provider/model-id --input-tokens 100000 --output-tokens 10000 --cache-read-tokens 50000
```

费用字段写在 `models[].cost.input/output/cacheRead/cacheWrite`，单位是美元 / 百万 tokens。定义 `cost` 时四类基础价格必须齐全；不需要展示费用时可省略整个 `cost`，默认按 `0` 处理。`cost.tiers[]` 每项也必须包含四类价格与非负整数 `inputTokensAbove`。

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
  --provider gateway \
  --api openai-completions \
  --base-url https://api.example.com/v1 \
  --model provider/model-id \
  --context-window 128000 \
  --max-tokens 16384 \
  --set-default

printf '%s' "$API_KEY" | repi model login --provider gateway --api-key-stdin
repi model doctor
repi model test --provider gateway --model provider/model-id
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
repi --provider gateway --model provider/model-id
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
- 因此 footer 显示超过 `auto@85%` 时，若模型正在持续吐 token，不会强行中断当前 stream；一旦当前 turn 结束，REPI 会在安全边界压缩已消费的历史，再继续后续 autonomous loop。


## 7. upstream pi 扩展兼容

REPI 可以安装使用 upstream pi 生态里采用 `package.json` `pi` manifest 的 npm/git 包，同时保持运行目录隔离。常用示例：

```bash
repi install npm:@narumitw/pi-goal
repi install npm:pi-web-access
repi list
```

兼容层已覆盖常见 upstream 包名：

```text
@earendil-works/pi-coding-agent
@earendil-works/pi-ai
@earendil-works/pi-ai/compat
@earendil-works/pi-ai/oauth
@earendil-works/pi-tui
@earendil-works/pi-agent-core
```

启动器会把 `PI_CODING_AGENT_DIR` / `PI_CODING_AGENT_SESSION_DIR` 映射到 `REPI_CODING_AGENT_DIR` / `REPI_CODING_AGENT_SESSION_DIR`。因此旧扩展读取 `PI_*` 路径时仍落在 `~/.repi/agent`，不会默认写入 `~/.pi`。需要浏览器 cookie 的搜索类扩展可设置：

```bash
export REPI_ALLOW_BROWSER_COOKIES=1
```

REPI 会在启动时把它转成兼容扩展识别的 `PI_ALLOW_BROWSER_COOKIES=1`。

## 8. 非交互长任务稳定性

`repi -p` / `repi --mode text` 默认启用长任务 guardrails，避免模型工具循环、慢 provider、stdin 未关闭或 bash 无超时导致“看起来卡死”。这些输出走 stderr，不污染最终 stdout。

| 变量 | 默认值 | 作用 |
|---|---:|---|
| `REPI_PRINT_PROGRESS` | `1` | 非交互 text 模式输出 `prompt_start`、tool start/end、compaction、retry 和 heartbeat。 |
| `REPI_PRINT_TIMEOUT_MS` | `210000` | 单个 prompt 的 wall timeout，超时后 abort 当前 agent run。 |
| `REPI_PRINT_MAX_TURNS` | `10` | 单个 prompt 的 turn 上限；最后一轮保留为无工具总结，防止长审计在墙钟超时前没有结论。 |
| `REPI_PRINT_MAX_TOOL_CALLS` | `48` | 单个 prompt 的 tool call 总量上限。 |
| `REPI_BASH_DEFAULT_TIMEOUT_SECONDS` | `120` | 模型调用 bash 但未显式传 `timeout` 时的默认超时。 |
| `REPI_STDIN_READ_TIMEOUT_MS` | `1500` | 非 TTY stdin 未关闭时的读取保护。 |
| `REPI_READ_STDIN_WITH_PROMPT` | unset | 设为 `1` 时，允许把 stdin 与显式 `-p`/message prompt 拼接。 |

示例：

```bash
REPI_PRINT_TIMEOUT_MS=300000 REPI_PRINT_MAX_TOOL_CALLS=120 repi -p "长任务"
REPI_BASH_DEFAULT_TIMEOUT_SECONDS=30 repi --tools bash -p "跑一个有边界的本地检查"
```

Provider stream idle timeout 使用同一套 provider timeout：`settings.retry.provider.timeoutMs` 或 HTTP idle timeout 设置；OpenAI Codex Responses SSE fallback 和 Anthropic-compatible SSE body read 都会在 idle 超时后取消 reader。

## 9. 常见故障

| 现象 | 处理 |
|---|---|
| `No models available` | 默认 catalog 为空；至少配置一组完整 `REPI_BASE_URL` + `REPI_MODEL`，或在 `models.json` / 扩展中显式注册模型。 |
| `No models match pattern` | 确认 env-only provider、`models.json` provider id 和 model id 与命令完全一致。 |
| `No API key found` | 确认 `REPI_AUTH_TOKEN` 或 `apiKey` 引用的环境变量已 export；需要持久化时运行 `repi model login --provider <id>`。 |
| JSON 环境变量解析失败 | 用单引号包住 `REPI_HEADERS`、`REPI_COMPAT`、thinking map、cost tiers 等 JSON，先用 `repi model status` 查看诊断。 |
| 上游不认识 `developer` role | 在 provider `compat` 里设置 `"supportsDeveloperRole": false`。 |
| 上游不认识 `reasoning_effort` | 设置 `"supportsReasoningEffort": false`。 |
| 上游不认识 `store` 或 tools strict | 设置 `"supportsStore": false`、`"supportsStrictMode": false`。 |
| 本地模型无 usage | 设置 `"supportsUsageInStreaming": false`，并确认 `contextWindow` 手动填对。 |
| 安装后 `repi: command not found` | 重新运行最新 `bash install.sh`。默认会优先安装到 PATH 里的 `/usr/local/bin`/`/usr/local/sbin`；若回退到 `~/.local/bin`，安装器会写入 shell rc，新终端自动生效。当前终端可先执行 `export PATH="$HOME/.local/bin:$PATH"`。 |

不要把真实 API key、GitHub token 或私有 endpoint 写入 README、示例或提交历史。
