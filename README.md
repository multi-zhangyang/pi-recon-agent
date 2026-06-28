# REPI Reverse/Pentest Agent

REPI 是独立的逆向渗透命令行智能体，主题是 reverse / pentest execution：逆向工程、漏洞验证、Web/API 渗透、pwn、移动、固件、流量/取证、恶意样本分析和可复现证据整理。它提供独立的 `repi` 命令、独立运行目录、可配置模型、多工具调用、MCP 接入、上下文压缩、任务记忆、子代理和工程化诊断能力。

REPI 已经和原版 `pi` agent 划开边界：它不是 `pi` 的 profile，也不是通用 coding agent。项目会复用成熟的工具调用、插件、MCP 和 subagent 机制，避免回到纯自研 agent 控制平面导致的臃肿。安装 REPI 不会覆盖本机已有的 `pi` 命令，运行数据默认写入 `~/.repi/agent`。

## 特性

- **独立命令**：使用 `repi` 启动；不接管、不删除、不覆盖用户已有的 `pi`。
- **逆向渗透工作流**：内置面向 recon、reverse、pwn、web/API、移动、固件、DFIR、协议分析和 exploit proof 的任务组织、工具策略与证据产物。
- **模型配置**：支持 OpenAI Chat Completions、OpenAI Responses、Anthropic Messages 兼容接口；支持自定义 base URL、上下文窗口、价格、缓存价格和默认模型。
- **上下文管理**：支持自动 compact、resume contract、跨会话恢复和上下文压缩配置。
- **MCP 接入**：支持 stdio / streamable HTTP MCP server，支持工具搜索、proxy 调用、resources、prompts、连接池、失败重连和输出脱敏。
- **子代理**：支持隔离 worker、并行专家任务、独立日志、证据合并和 MCP 配置继承/限制。
- **记忆治理**：支持作用域隔离、沉淀、查询、清理、修复和导出，避免跨任务污染。
- **诊断工具**：提供 `doctor`、`smoke`、`selfcheck`、`bugreport` 等普通用户命令。

## 安装

### 从源码安装

```bash
git clone https://github.com/multi-zhangyang/pi-recon-agent.git
cd pi-recon-agent
npm install
npm run install:repi
```

安装后检查：

```bash
repi --offline --help
repi --offline --list-models
repi doctor
```

### 更新已有安装

```bash
cd /path/to/pi-recon-agent
git pull
npm install
npm run install:repi
repi doctor
```

## 常用命令

```bash
repi                         # 交互式启动
repi -p "分析这个项目结构"      # 非交互一次性任务
repi --offline --help        # 查看帮助，不调用模型
repi doctor                  # 检查安装、配置、权限和常见问题
repi smoke --json            # 本地快速 smoke
repi selfcheck --deep        # 更完整的本机自检
repi bugreport --stdout      # 生成脱敏诊断信息
```

## 模型配置

REPI 的模型配置在：

```text
~/.repi/agent/models.json
~/.repi/agent/auth.json
```

推荐通过命令写入本地配置，不要把密钥写进仓库：

```bash
repi model add my-openai \
  --api openai-completions \
  --base-url https://api.example.com/v1 \
  --model gpt-4.1 \
  --context-window 128000 \
  --max-tokens 8192

printf '%s' "$API_KEY" | repi model login my-openai --api-key-stdin
repi model default my-openai/gpt-4.1
repi model test my-openai/gpt-4.1
```

### OpenAI Chat Completions 兼容

```json
{
  "providers": {
    "my-openai": {
      "api": "openai-completions",
      "baseUrl": "https://api.example.com/v1",
      "models": {
        "gpt-4.1": {
          "contextWindow": 128000,
          "maxTokens": 8192,
          "input": ["text", "image"],
          "reasoning": true,
          "cost": {
            "input": 2,
            "output": 8,
            "cacheRead": 0.5,
            "cacheWrite": 2
          }
        }
      }
    }
  },
  "defaultModel": "my-openai/gpt-4.1"
}
```

### OpenAI Responses 兼容

```json
{
  "providers": {
    "my-responses": {
      "api": "openai-responses",
      "baseUrl": "https://api.example.com/v1",
      "models": {
        "o4-mini": {
          "contextWindow": 200000,
          "maxTokens": 8192,
          "reasoning": true
        }
      }
    }
  }
}
```

### Anthropic Messages 兼容

```json
{
  "providers": {
    "my-anthropic": {
      "api": "anthropic-messages",
      "baseUrl": "https://api.example.com",
      "models": {
        "claude-sonnet-4": {
          "contextWindow": 200000,
          "maxTokens": 8192,
          "reasoning": true
        }
      }
    }
  }
}
```

查看和诊断：

```bash
repi model list
repi model doctor
repi model cost my-openai/gpt-4.1 --input 100000 --output 8000
```

## MCP 配置

MCP 配置文件：

```text
~/.repi/agent/mcp.json
<project>/.repi/mcp.json
```

示例：

```json
{
  "mcpServers": {
    "browser-tools": {
      "transport": "stdio",
      "command": "npx",
      "args": ["-y", "some-mcp-server"],
      "env": {
        "EXAMPLE_TOKEN": "$EXAMPLE_TOKEN"
      },
      "autoRegisterTools": true,
      "deferToolSchemas": true,
      "timeoutMs": 30000,
      "poolIdleMs": 15000
    },
    "remote-tools": {
      "transport": "http",
      "url": "https://mcp.example.com/mcp",
      "headers": {
        "Authorization": "Bearer $MCP_API_KEY"
      },
      "autoRegisterTools": true,
      "deferToolSchemas": true
    }
  }
}
```

常用命令：

```bash
repi mcp status
repi mcp list
repi mcp probe browser-tools
repi mcp search browser-tools browser
repi mcp call browser-tools call_tool '{"name":"browser_status","args":{}}'
repi mcp resources browser-tools
repi mcp read-resource browser-tools 'file:///demo.txt'
repi mcp prompts browser-tools
repi mcp get-prompt browser-tools triage '{"target":"example.test"}'
repi mcp auth-info remote-tools
```

对 search/router 模式 MCP：`mcp__server__call.tool` 必须填写 MCP 当前 `tools/list` 真实暴露的工具名。若搜索结果提示 `call_tool({ name: "browser_status", args: {} })`，则 proxy 参数应是：

```json
{
  "tool": "call_tool",
  "arguments": {
    "name": "browser_status",
    "args": {}
  }
}
```

REPI 会复用 MCP session，并在 stdio wrapper 关闭时清理整个进程组，避免 `xvfb-run`、`npm exec`、浏览器 wrapper 这类子进程残留。

## 上下文压缩

配置文件位于 `~/.repi/agent/settings.json`，常用配置：

```json
{
  "compaction": {
    "enabled": true,
    "triggerPercent": 85,
    "autoResume": true
  }
}
```

查看当前上下文状态可在交互界面中使用 `/context`、`/compact` 等命令。

## 子代理与并行

```bash
repi swarm plan ./target --workers 4
repi swarm run ./target --workers 4
repi swarm status
repi swarm merge <run-id>
```

子代理默认使用独立运行目录，输出 stdout/stderr、manifest 和 merge artifact。MCP 配置可继承，也可以通过 worker allowlist 限制。

## 记忆管理

```bash
repi memory status
repi memory list
repi memory show <id>
repi memory why <query>
repi memory purge --dry-run
repi memory repair --dry-run
```

默认策略是作用域隔离：项目、目标、任务不匹配的记忆不会主动注入，避免旧任务污染新任务。

## 开发检查

普通开发只需要：

```bash
npm run check
node scripts/reverse-agent/repi-smoke.mjs . --json
```

这些检查不依赖私有模型、不要求外部凭据、不访问真实目标，也不依赖某个特定 MCP。

## 目录

```text
packages/coding-agent/      REPI CLI 和核心 agent runtime
packages/agent-core/        agent core types/runtime
packages/tui/               终端 UI
scripts/reverse-agent/      安装、诊断、smoke、运行时辅助脚本
repi-profile/               默认 REPI profile、prompt、配置说明
docs/                       使用文档和设计说明
```

## 隐私与配置

- 不要提交 `~/.repi/agent/auth.json`、真实 API key、私有 base URL、cookie、session、HAR、浏览器 profile。
- 文档和示例只使用占位符。
- `repi bugreport` 默认做脱敏处理，适合提交 issue 前检查。

## License

见仓库许可证文件。
