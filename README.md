<h1 align="center">REPI</h1>

<p align="center">
  面向逆向工程、渗透测试与数字取证的本地智能体平台
</p>

<p align="center">
  <a href="https://github.com/multi-zhangyang/pi-recon-agent/actions/workflows/repi-ci.yml"><img src="https://github.com/multi-zhangyang/pi-recon-agent/actions/workflows/repi-ci.yml/badge.svg" alt="REPI CI"></a>
  <a href="https://github.com/multi-zhangyang/pi-recon-agent/releases"><img src="https://img.shields.io/github/v/release/multi-zhangyang/pi-recon-agent?display_name=tag" alt="Release"></a>
  <a href="https://github.com/multi-zhangyang/pi-recon-agent/blob/main/LICENSE"><img src="https://img.shields.io/github/license/multi-zhangyang/pi-recon-agent" alt="License"></a>
  <img src="https://img.shields.io/badge/Node.js-%3E%3D22.19-339933?logo=node.js&logoColor=white" alt="Node.js >= 22.19">
</p>

<p align="center">
  <a href="#项目概览">项目概览</a> ·
  <a href="#安装">安装</a> ·
  <a href="#模型配置">模型配置</a> ·
  <a href="#使用方式">使用方式</a> ·
  <a href="#扩展与集成">扩展与集成</a> ·
  <a href="#开发与发布">开发与发布</a>
</p>

## 项目概览

REPI 在终端中连接模型、项目上下文和本地安全工具，为长时间、多阶段的技术任务提供统一执行环境。平台覆盖目标识别、任务拆分、工具调用、证据归档、结论验证、会话恢复和步骤重放，适用于安全研究、工程审计、问题复现与分析自动化。

模型负责分析和决策，运行时负责执行与状态管理。命令输出、网络流量、调试记录和生成文件等实际运行产物作为验证依据，模型文本本身不被视为已验证证据。

REPI 以本地部署为默认工作方式。源文件、工具进程、会话数据和任务产物保留在用户环境中；只有提交给所选模型服务的上下文会离开本机。

## 适用场景

| 领域 | 主要工作 | 典型产物 |
| --- | --- | --- |
| Native / Pwn | ELF、PE、Mach-O、保护机制、交叉引用、调试与崩溃分析 | 保护机制清单、寄存器状态、偏移、PoC 重放记录 |
| Web / API | 路由、认证授权、请求状态机、XHR、WebSocket、浏览器运行时 | 路由图、身份矩阵、请求序列、响应摘要 |
| Mobile | APK、IPA、ADB、Frida、Java 与 Native hook、反调试 | Manifest 信息、hook 记录、静态与运行时差异 |
| Firmware / IoT | 固件识别、文件系统提取、启动项、服务与配置分析 | 文件系统映射、服务清单、配置与二进制引用 |
| PCAP / DFIR | 流重组、协议提取、时间线、内存与磁盘分析 | 会话流、IOC、提取文件、事件链 |
| Malware | 样本静态分析、行为线索、IOC 与规则整理 | 导入表、字符串、行为映射、YARA 规则 |
| Crypto / Stego | 变换链、参数恢复、约束求解、签名与结果校验 | 已知答案测试、求解记录、首个差异点 |
| Cloud / Identity | Token 流、凭据验证、权限边界与部署状态分析 | 主体信息、策略关系、凭据检查、访问路径 |

## 核心能力

### 可追踪的执行闭环

每项任务由目标、范围、执行步骤、产物和完成条件组成。REPI 将命令、工具结果、文件产物、声明和验证记录关联起来，便于检查结论来源并重放关键步骤。

```text
Target -> Mission -> Domain Adapter -> Runtime -> Evidence -> Verifier -> Replay
```

当信息冲突时，系统按实际运行状态、网络流量、当前服务资源、进程配置、持久化产物和源码的顺序评估证据。证据不足、工具缺失或环境受限时，任务状态会保留阻塞原因和后续动作，不生成替代性的成功结果。

### 长任务与会话管理

- 自动保存会话，并支持继续、检索、分支、克隆和树形导航。
- 支持上下文压缩、检查点、待处理写入和进程重启恢复。
- 长任务可以设置 token 预算、完成条件和明确的完成状态。
- 子任务通过隔离 worker 执行，保留超时、取消、重试和交接信息。

### 多入口运行

REPI 提供交互式终端、一次性输出、JSON 事件流、RPC 和 TypeScript SDK。相同的会话与工具运行时可用于人工操作、脚本编排、持续集成或上层应用集成。

### 明确的模型协议

平台支持 OpenAI Chat Completions、OpenAI Responses 和 Anthropic Messages。协议、模型、上下文窗口、请求头与兼容参数均由配置显式指定，不依赖静默协议切换。

## 系统架构

REPI 采用 monorepo 管理四个运行时包，并通过发布契约保持版本一致。

| 模块 | 职责 |
| --- | --- |
| `packages/ai` | Provider、模型目录、协议适配与流式响应 |
| `packages/agent` | Agent Harness、工具循环、消息状态、重试与压缩 |
| `packages/tui` | 终端组件、输入处理与增量渲染 |
| `packages/coding-agent` | CLI、交互界面、领域运行时、扩展系统与 SDK |
| `scripts/reverse-agent` | 安装、诊断、契约检查、smoke 与发布工具 |

AI 层不持有任务状态；Agent Core 管理模型与工具循环；Coding Agent 负责装配用户入口、领域能力和扩展资源。任务状态使用 SQLite WAL 管理，JSON、Markdown、HAR 和可执行脚本用于导出、交换与重放。

## 安装

### 环境要求

| 项目 | 要求 |
| --- | --- |
| 操作系统 | Linux、macOS 或 WSL |
| Node.js | `>= 22.19.0` |
| 基础工具 | Git、npm |

### 一键安装

```bash
curl -fsSL https://raw.githubusercontent.com/multi-zhangyang/pi-recon-agent/main/install.sh | bash
```

安装器会拉取源码、安装依赖、生成运行入口并执行离线启动检查。如果启动脚本写入了新的 PATH 配置，终端会显示：

```text
Successfully added repi to $PATH in ~/.bashrc
```

此时加载对应的 shell 配置，或打开新的终端：

```bash
source ~/.bashrc
```

### 从源码安装

```bash
git clone https://github.com/multi-zhangyang/pi-recon-agent.git
cd pi-recon-agent
bash install.sh
```

安装完成后执行离线检查：

```bash
repi --offline --help
repi --offline --list-models
```

## 模型配置

### 环境变量

REPI 支持 Claude Code 风格的环境变量配置。以下示例接入 OpenAI-compatible 服务：

```bash
export REPI_AUTH_TOKEN="sk-..."
export REPI_BASE_URL="https://api.example.com/v1"
export REPI_MODEL="provider/model-id"
export REPI_MODEL_API="openai-compatible"
export REPI_CONTEXT_WINDOW=262144

repi model doctor
repi doctor
```

`REPI_MODEL_API` 支持以下值：

| 配置值 | 对应协议 |
| --- | --- |
| `openai-compatible` | OpenAI Chat Completions |
| `openai-responses` | OpenAI Responses |
| `anthropic` | Anthropic Messages |

常用环境变量：

| 变量 | 用途 |
| --- | --- |
| `REPI_AUTH_TOKEN` | 模型服务凭据 |
| `REPI_BASE_URL` | Provider 根地址 |
| `REPI_PROVIDER` | Provider 标识 |
| `REPI_MODEL` | 模型标识 |
| `REPI_MODEL_API` | 请求协议 |
| `REPI_CONTEXT_WINDOW` | 上下文窗口 |
| `REPI_MAX_TOKENS` | 单次输出上限 |
| `REPI_SUBAGENT_MODEL` | 子任务使用的模型 |

### 持久化 Provider

需要管理多个 Provider、自定义请求头、成本信息或兼容参数时，可使用命令写入 `~/.repi/agent/models.json`：

```bash
repi model add \
  --provider gateway \
  --api openai-completions \
  --base-url https://api.example.com/v1 \
  --model provider/model-id \
  --context-window 128000 \
  --max-tokens 16384

printf '%s' "$GATEWAY_API_KEY" | repi model login --provider gateway --api-key-stdin
repi model doctor
repi model test --provider gateway --model provider/model-id
```

环境变量、`models.json` 字段、Header 配置和协议兼容参数见[运行时配置](docs/reverse-agent/repi-runtime-configuration.md)。

## 使用方式

### 交互模式

在目标目录启动 REPI：

```bash
cd /path/to/target
repi
```

交互界面支持文件引用、工具调用、模型切换、会话导航和上下文管理。创建具有预算和完成条件的长任务：

```text
/goal --tokens 100k 分析目标，验证关键路径，并输出可复现证据
```

### 命令行入口

| 命令 | 用途 |
| --- | --- |
| `repi` | 启动交互模式 |
| `repi -p "分析 ./target"` | 执行一次性任务并输出结果 |
| `repi -c` | 继续最近一次会话 |
| `repi -r` | 选择历史会话 |
| `repi --mode json -p "审计当前项目"` | 输出 JSON 事件流 |
| `repi --mode rpc` | 启动基于标准输入输出的 RPC 服务 |

### 会话操作

| 命令 | 用途 |
| --- | --- |
| `/resume` | 打开历史会话 |
| `/tree` | 浏览当前会话树并切换节点 |
| `/fork` | 从历史消息创建独立会话 |
| `/clone` | 克隆当前活动分支 |
| `/compact` | 压缩较早的上下文 |
| `/session` | 查看当前会话信息 |

### 项目指令

REPI 会读取用户目录中的 `~/.repi/agent/AGENTS.md`，并在项目受信任后读取工作目录及父目录中的 `AGENTS.md` 或 `CLAUDE.md`。项目指令可用于定义工程规范、验证命令、工具约束和交付格式。

## 数据与运维

运行数据默认保存在 `~/.repi/agent`：

| 路径 | 内容 |
| --- | --- |
| `models.json` | Provider 与模型定义 |
| `settings.json` | 运行偏好与上下文配置 |
| `auth.json` | 本地凭据与登录状态 |
| `sessions/` | 按工作目录组织的会话 |
| `recon/` | Mission、证据和领域任务产物 |

常用诊断命令：

```bash
repi doctor
repi smoke
repi model doctor
repi bugreport --stdout
```

诊断包提交前应检查并移除凭据、私有端点、会话内容和目标数据。问题反馈流程见 [SUPPORT.md](SUPPORT.md)。

## 扩展与集成

REPI 兼容扩展、skills、prompt templates、主题和 MCP 服务。扩展可以注册工具、命令、Provider 和界面组件，并通过项目级或用户级配置加载。

```bash
repi install npm:pi-web-access
repi list
```

MCP 配置可放在 `~/.repi/agent/mcp.json` 或项目内的 `.repi/mcp.json`：

```json
{
  "mcpServers": {
    "browser-tools": {
      "transport": "stdio",
      "command": "npx",
      "args": ["-y", "some-mcp-server"],
      "autoRegisterTools": true,
      "deferToolSchemas": true
    }
  }
}
```

接口文档：

- [扩展](packages/coding-agent/docs/extensions.md)
- [Skills](packages/coding-agent/docs/skills.md)
- [SDK](packages/coding-agent/docs/sdk.md)
- [RPC](packages/coding-agent/docs/rpc.md)
- [MCP](packages/coding-agent/docs/recon.md)

## 开发与发布

### 本地开发

```bash
git clone https://github.com/multi-zhangyang/pi-recon-agent.git
cd pi-recon-agent
npm ci --ignore-scripts
npm run check
npm test
```

用户入口与发布产物验证：

```bash
npm run smoke:repi -- --json
npm run smoke:install-path -- --json
npm run smoke:extensions -- --json
npm run smoke:release -- . --json
```

代码规范与提交要求见 [CONTRIBUTING.md](CONTRIBUTING.md) 和 [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)。

### 发布产物

GitHub Release 同时提供 AI、Agent Core、TUI 和 Coding Agent 四个同版本 tarball，以及记录文件名、大小、SHA-256 和安装命令的 `repi-release-manifest.json`。四个包必须使用相同版本并在同一条命令中安装。

```bash
npm install -g \
  pi-recon-repi-ai-<version>.tgz \
  pi-recon-repi-agent-core-<version>.tgz \
  pi-recon-repi-tui-<version>.tgz \
  pi-recon-repi-coding-agent-<version>.tgz
```

## 文档

| 文档 | 内容 |
| --- | --- |
| [快速开始](packages/coding-agent/docs/quickstart.md) | 安装、认证与首个会话 |
| [使用指南](packages/coding-agent/docs/usage.md) | 交互模式、命令行与会话操作 |
| [模型与 Provider](packages/coding-agent/docs/providers.md) | Provider、认证和模型接入 |
| [运行时配置](docs/reverse-agent/repi-runtime-configuration.md) | `REPI_*`、`models.json` 与兼容参数 |
| [Agent Harness](packages/agent/docs/agent-harness.md) | 工具循环、会话、压缩与恢复 |
| [安全政策](SECURITY.md) | 安全问题报告与敏感数据处理 |
| [支持与反馈](SUPPORT.md) | 自助诊断与问题反馈 |

## 安全与隐私

REPI 以当前用户权限读取文件、执行命令并调用已配置的模型服务。项目配置、第三方扩展、skills 和 MCP 服务会影响运行时可访问的资源，应按实际部署环境进行审查和版本管理。

不要在公开 Issue、日志或截图中提交 API key、token、cookie、HAR、浏览器 profile、私有目标数据或 `~/.repi/agent/auth.json`。安全问题通过 GitHub Security Advisory 私密报告，具体流程见 [SECURITY.md](SECURITY.md)。

## License

[MIT](LICENSE)
