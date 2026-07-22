<p align="center">
  <a href="https://github.com/multi-zhangyang/pi-recon-agent">
    <img src="packages/coding-agent/docs/images/repi-logo.svg" width="128" alt="REPI 标志">
  </a>
</p>

<h1 align="center">REPI</h1>

<p align="center">
  面向逆向工程、漏洞研究与数字取证的自主终端智能体
</p>

<p align="center">
  <a href="https://github.com/multi-zhangyang/pi-recon-agent/actions/workflows/repi-ci.yml"><img src="https://github.com/multi-zhangyang/pi-recon-agent/actions/workflows/repi-ci.yml/badge.svg" alt="CI 状态"></a>
  <a href="https://github.com/multi-zhangyang/pi-recon-agent/releases"><img src="https://img.shields.io/github/v/release/multi-zhangyang/pi-recon-agent?display_name=tag" alt="最新版本"></a>
  <a href="https://github.com/multi-zhangyang/pi-recon-agent/blob/main/LICENSE"><img src="https://img.shields.io/github/license/multi-zhangyang/pi-recon-agent" alt="MIT License"></a>
  <img src="https://img.shields.io/badge/Node.js-%3E%3D22.19-339933?logo=node.js&logoColor=white" alt="Node.js >= 22.19">
</p>

<p align="center">
  <a href="#快速开始">快速开始</a> ·
  <a href="#能力范围">能力范围</a> ·
  <a href="#执行模型">执行模型</a> ·
  <a href="#扩展与集成">扩展与集成</a> ·
  <a href="#参与开发">参与开发</a>
</p>

REPI 把大模型、终端工具和可持久化任务状态组合成一条完整的安全工程工作流。它可以在同一会话内识别目标、规划路径、执行工具、保存证据、验证结论并生成可重放步骤，适合需要真实运行环境和长任务恢复能力的研究工作。

<p align="center">
  <img src="packages/coding-agent/docs/images/interactive-mode.png" width="880" alt="REPI 交互式终端界面">
</p>

## 主要特性

- **真实执行**：调用本机命令、浏览器、调试器、反编译器与取证工具，不以模型猜测代替运行结果。
- **证据闭环**：将结论关联到命令输出、artifact、哈希、请求重放、negative control 和 verifier。
- **领域化运行时**：Native、Web、Mobile、Firmware、DFIR、Malware、Crypto 与 Cloud 使用各自的 adapter、工具链和证明出口。
- **长会话恢复**：任务状态、checkpoint、压缩摘要、pending writes 和 worker handoff 可跨轮次持续推进。
- **有界多智能体**：通过 claim、lease、重试预算、artifact 合并和 supervisor review 协作，避免无边界扩散。
- **开放集成**：提供交互终端、一次性命令、JSON/RPC、SDK、MCP、skills 和扩展 API。

## 快速开始

### 环境要求

- Linux、macOS 或 WSL
- Node.js `>= 22.19.0`
- Git

### 安装

```bash
curl -fsSL https://raw.githubusercontent.com/multi-zhangyang/pi-recon-agent/main/install.sh | bash
source ~/.bashrc
```

安装器会拉取源码、构建四个运行时包、安装 `repi` 启动器并执行离线检查。首次配置 shell PATH 时会看到：

```text
Successfully added repi to $PATH in ~/.bashrc
```

从已有仓库安装：

```bash
git clone https://github.com/multi-zhangyang/pi-recon-agent.git
cd pi-recon-agent
bash install.sh
```

### 配置模型

REPI 支持 OpenAI Chat Completions、OpenAI Responses 和 Anthropic Messages 协议。OpenAI-compatible 服务可使用 Claude Code 风格的环境变量完成配置：

```bash
export REPI_AUTH_TOKEN="sk-..."
export REPI_BASE_URL="https://api.example.com/v1"
export REPI_MODEL="provider/model-id"
export REPI_MODEL_API="openai-compatible"
export REPI_CONTEXT_WINDOW=262144
export REPI_MAX_TOKENS=16384

repi model status
repi doctor
```

| `REPI_MODEL_API` | 协议 |
| --- | --- |
| `openai-compatible` | OpenAI Chat Completions |
| `openai-responses` | OpenAI Responses |
| `anthropic` | Anthropic Messages |

需要管理多个 provider、自定义请求头、模型元数据或价格时，使用 `~/.repi/agent/models.json`。详见[模型运行时配置](docs/reverse-agent/repi-runtime-configuration.md)。

### 启动任务

在目标目录运行：

```bash
cd /path/to/target
repi
```

交互会话中可以直接描述任务，也可以创建带预算和完成条件的长任务：

```text
/goal --tokens 100k 分析目标，定位可利用路径，并输出可复现证据
```

常用启动方式：

```bash
repi -p "分析 ./target，验证关键结论并给出重放步骤"
repi -c                              # 继续最近会话
repi -r                              # 选择历史会话
repi --mode json -p "审计当前项目"  # 结构化事件流
repi --mode rpc                      # 进程集成
```

安装完成后建议先运行：

```bash
repi doctor
repi model doctor
repi --offline --help
```

## 能力范围

| 领域 | 运行能力 | 典型证据 |
| --- | --- | --- |
| Native / Pwn | ELF、PE、Mach-O、保护机制、GDB、xref、崩溃与利用原语 | 寄存器、offset、mitigation map、PoC replay |
| Web / API | Playwright/CDP、HAR、XHR/WS、认证授权、对象所有权与状态机 | route graph、principal matrix、请求顺序、响应哈希 |
| Mobile | APK/IPA、ADB、Frida、Java/Native hook、反调试 | manifest、hook transcript、运行时差异 |
| Firmware / IoT | 固件识别、文件系统提取、服务与配置分析 | rootfs map、启动项、二进制与凭据引用 |
| PCAP / DFIR | 流重组、协议提取、时间线、内存与磁盘 artifact | conversation、IOC、提取文件、事件链 |
| Malware | 样本静态分析、行为线索、IOC 与规则生成 | import、string、行为映射、YARA |
| Crypto / Stego | 变换链、参数恢复、约束求解与签名验证 | known-answer、solver、首个差异点 |
| Cloud / Identity | Token 流、凭据可用性、权限边界与部署事实 | principal、policy、credential check、pivot chain |

REPI 不会把缺少运行证据的推测提升为已验证结论。目标、凭据或工具不足时，任务会保留明确 blocker 和下一条可执行动作。

## 执行模型

```text
Target
  -> Mission & Router
  -> Domain Adapter
  -> Tool / Browser / Debugger Runtime
  -> Evidence Graph
  -> Verifier
  -> Replay & Report
```

| 层 | 职责 |
| --- | --- |
| Mission | 保存目标、范围、lane、checkpoint 和完成条件 |
| Router | 根据任务与 artifact 选择专业领域和执行路径 |
| Domain Adapter | 统一目标解析、runner、artifact、验证与 replay 协议 |
| Runtime | 执行本地工具、浏览器上下文、调试器或隔离 worker |
| Evidence Graph | 连接命令、输出、artifact、声明、反证和来源 |
| Verifier | 检查证据完整性、矛盾、negative control 与证明出口 |
| Replay | 固化环境、输入、步骤和结果哈希，验证结论可复现 |

证据优先级遵循实际运行状态：

```text
live runtime > network traffic > served assets > process configuration > persisted artifacts > source
```

运行数据默认位于 `~/.repi/agent`。核心任务状态使用 SQLite WAL 持久化；JSON、Markdown、HAR 和脚本作为可阅读、可导出、可重放的 artifact。

## 工作界面

| 接口 | 用途 |
| --- | --- |
| Interactive TUI | 日常研究、工具审批、模型切换、会话树与长任务 |
| Print mode | 脚本化的一次性任务 |
| JSON mode | CI、日志采集和事件消费 |
| RPC mode | 编辑器、服务和其他进程集成 |
| SDK | 在 TypeScript 应用中创建 session 与自定义运行时 |
| MCP | 接入外部工具服务器，并延迟加载大型 schema |

会话自动保存，可使用 `/resume`、`/tree`、`/fork`、`/clone` 和 `/compact` 管理历史与上下文。完整命令见 [Usage](packages/coding-agent/docs/usage.md) 和 [Sessions](packages/coding-agent/docs/sessions.md)。

## 扩展与集成

REPI 兼容 Pi 扩展生态，并支持自定义工具、命令、provider、UI、skills 和 prompt templates。

```bash
repi install npm:pi-web-access
repi list
```

MCP 配置可放在全局 `~/.repi/agent/mcp.json` 或项目 `.repi/mcp.json`：

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

相关文档：[Extensions](packages/coding-agent/docs/extensions.md) · [MCP](packages/coding-agent/docs/recon.md) · [Skills](packages/coding-agent/docs/skills.md) · [SDK](packages/coding-agent/docs/sdk.md)

## 项目结构

```text
packages/coding-agent/   CLI、TUI、REPI 专业运行时与 SDK
packages/agent/          AgentHarness、AgentSession、工具循环与压缩
packages/ai/             Provider、协议、模型目录与流式响应
packages/tui/            终端渲染组件
scripts/reverse-agent/   安装、诊断、契约、smoke 与发布工具
docs/reverse-agent/      REPI 架构和运行时文档
```

各层通过显式协议连接：AI 包不负责会话，Agent Core 不包含产品 UI，Coding Agent 负责装配运行时与用户入口，领域能力通过统一 DomainAdapter 执行协议接入。

## 参与开发

```bash
git clone https://github.com/multi-zhangyang/pi-recon-agent.git
cd pi-recon-agent
npm ci --ignore-scripts
npm run check
```

常用验证命令：

```bash
npm test
npm run smoke:repi -- --json
npm run smoke:install-path -- --json
npm run smoke:extensions -- --json
npm run smoke:release -- . --json
```

提交 Pull Request 前请阅读 [CONTRIBUTING.md](CONTRIBUTING.md) 和 [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)。CI 会检查格式、类型、依赖锁定、运行时契约、测试分片、安装路径、扩展兼容性、发布包和生产依赖漏洞。

## 发布与升级

每个 GitHub Release 包含同版本的 AI、Agent Core、TUI 和 Coding Agent tarball，以及记录文件大小、SHA-256 和安装命令的 `repi-release-manifest.json`。四个包必须使用同一版本并一起安装：

```bash
npm install -g \
  pi-recon-repi-ai-<version>.tgz \
  pi-recon-repi-agent-core-<version>.tgz \
  pi-recon-repi-tui-<version>.tgz \
  pi-recon-repi-coding-agent-<version>.tgz
```

源码安装可使用内置更新器：

```bash
repi update
```

## 文档

| 文档 | 内容 |
| --- | --- |
| [Quickstart](packages/coding-agent/docs/quickstart.md) | 安装、认证与首个会话 |
| [Usage](packages/coding-agent/docs/usage.md) | 交互模式、命令行和会话管理 |
| [Providers](packages/coding-agent/docs/providers.md) | Provider、认证和模型接入 |
| [Runtime Configuration](docs/reverse-agent/repi-runtime-configuration.md) | `REPI_*`、`models.json` 和协议配置 |
| [Agent Harness](packages/agent/docs/agent-harness.md) | Agent loop、session、compaction 与恢复 |
| [Extensions](packages/coding-agent/docs/extensions.md) | 扩展 API、工具、命令与 UI |
| [Security](SECURITY.md) | 安全策略和漏洞报告 |
| [Support](SUPPORT.md) | 自助诊断和问题反馈 |

## 安全

REPI 会以当前用户权限读取文件、执行命令并调用配置的模型服务。不要在公开 Issue、日志或截图中提交 API key、cookie、session、HAR、浏览器 profile、私有目标数据或 `~/.repi/agent/auth.json`。

安全漏洞请通过 GitHub Security Advisory 私密报告，具体流程见 [SECURITY.md](SECURITY.md)。

## License

[MIT](LICENSE)
