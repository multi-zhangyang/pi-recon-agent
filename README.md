<h1 align="center">REPI</h1>

<p align="center">
  面向逆向工程、渗透测试与数字取证的本地自主智能体
</p>

<p align="center">
  <a href="https://github.com/multi-zhangyang/pi-recon-agent/actions/workflows/repi-ci.yml"><img src="https://github.com/multi-zhangyang/pi-recon-agent/actions/workflows/repi-ci.yml/badge.svg" alt="REPI CI"></a>
  <a href="https://github.com/multi-zhangyang/pi-recon-agent/releases"><img src="https://img.shields.io/github/v/release/multi-zhangyang/pi-recon-agent?display_name=tag" alt="Release"></a>
  <a href="https://github.com/multi-zhangyang/pi-recon-agent/blob/main/LICENSE"><img src="https://img.shields.io/github/license/multi-zhangyang/pi-recon-agent" alt="License"></a>
  <img src="https://img.shields.io/badge/Node.js-%3E%3D22.19-339933?logo=node.js&logoColor=white" alt="Node.js >= 22.19">
</p>

<p align="center">
  <a href="#快速开始">快速开始</a> ·
  <a href="#核心能力">核心能力</a> ·
  <a href="#执行架构">执行架构</a> ·
  <a href="#扩展与集成">扩展与集成</a> ·
  <a href="#参与开发">参与开发</a>
</p>

REPI 在终端中连接大模型与本地安全工具。它负责目标识别、任务路由、工具执行、证据归档、结论验证和步骤重放，适用于需要长会话、真实运行环境和可复现结果的安全研究任务。

REPI 以本地执行为核心：模型负责决策，运行时负责操作，artifact 和 verifier 负责证明。没有运行证据的推测不会被标记为已验证结果。

## 快速开始

### 安装

要求 Linux、macOS 或 WSL，Node.js `>= 22.19.0`，以及 Git。

```bash
curl -fsSL https://raw.githubusercontent.com/multi-zhangyang/pi-recon-agent/main/install.sh | bash
source ~/.bashrc
```

首次写入 PATH 时，安装器会输出：

```text
Successfully added repi to $PATH in ~/.bashrc
```

也可以从源码安装：

```bash
git clone https://github.com/multi-zhangyang/pi-recon-agent.git
cd pi-recon-agent
bash install.sh
```

### 配置模型

REPI 支持 OpenAI Chat Completions、OpenAI Responses 和 Anthropic Messages 协议。OpenAI-compatible 服务可使用 Claude Code 风格的环境变量：

```bash
export REPI_AUTH_TOKEN="sk-..."
export REPI_BASE_URL="https://api.example.com/v1"
export REPI_MODEL="provider/model-id"
export REPI_MODEL_API="openai-compatible"
export REPI_CONTEXT_WINDOW=262144

repi model doctor
repi doctor
```

`REPI_MODEL_API` 可设为：

| 值 | 协议 |
| --- | --- |
| `openai-compatible` | OpenAI Chat Completions |
| `openai-responses` | OpenAI Responses |
| `anthropic` | Anthropic Messages |

多 provider、自定义 header 和模型元数据使用 `~/.repi/agent/models.json`。详见[运行时配置](docs/reverse-agent/repi-runtime-configuration.md)。

### 开始任务

```bash
cd /path/to/target
repi
```

交互模式中直接输入任务，或创建有预算、有完成条件的长任务：

```text
/goal --tokens 100k 分析目标，验证关键路径，并输出可复现证据
```

其他入口：

```bash
repi -p "分析 ./target，验证关键结论并给出重放步骤"
repi -c                              # 继续最近会话
repi -r                              # 选择历史会话
repi --mode json -p "审计当前项目"  # JSON 事件流
repi --mode rpc                      # RPC 服务
```

## 核心能力

| 领域 | 能力 | 证据出口 |
| --- | --- | --- |
| Native / Pwn | ELF、PE、Mach-O、保护机制、xref、调试与崩溃分析 | mitigation map、寄存器、offset、PoC replay |
| Web / API | Playwright/CDP、HAR、XHR/WS、认证授权与状态机 | route graph、principal matrix、请求顺序、响应哈希 |
| Mobile | APK/IPA、ADB、Frida、Java/Native hook、反调试 | manifest、hook transcript、运行时差异 |
| Firmware / IoT | 固件识别、文件系统提取、服务与配置分析 | rootfs map、启动项、二进制与配置引用 |
| PCAP / DFIR | 流重组、协议提取、时间线、内存与磁盘 artifact | conversation、IOC、提取文件、事件链 |
| Malware | 样本静态分析、行为线索、IOC 与规则 | import、string、行为映射、YARA |
| Crypto / Stego | 变换链、参数恢复、约束求解与签名验证 | known-answer、solver、first divergence |
| Cloud / Identity | Token 流、凭据可用性、权限边界与部署状态 | principal、policy、credential check、pivot chain |

所有领域共用同一条工作主线：

```text
Target -> Mission -> Domain Adapter -> Runtime -> Evidence -> Verifier -> Replay
```

- **Mission** 保存目标、范围、lane、checkpoint 和完成条件。
- **Domain Adapter** 统一目标解析、runner、artifact、验证和 replay 协议。
- **Runtime** 执行本地工具、浏览器、调试器或隔离 worker。
- **Evidence** 连接命令、输出、artifact、声明、来源和反证。
- **Verifier** 检查证据完整性、矛盾与 negative control。
- **Replay** 固化输入、环境、步骤和结果哈希。

## 执行架构

REPI 是由四个独立运行时组成的 monorepo：

```text
packages/ai/             Provider、协议、模型目录与流式响应
packages/agent/          AgentHarness、AgentSession、工具循环与压缩
packages/tui/            终端渲染组件
packages/coding-agent/   CLI、交互界面、REPI 领域运行时与 SDK
scripts/reverse-agent/   安装、诊断、契约、smoke 与发布工具
```

核心边界：

- AI 包只处理模型协议，不持有任务状态。
- Agent Core 管理消息、工具调用、重试、压缩和 session 生命周期。
- Coding Agent 装配终端、扩展、领域工具和用户入口。
- REPI 专业能力通过统一 DomainAdapter 协议执行。
- 核心任务状态使用 SQLite WAL；JSON、Markdown、HAR 和脚本用于导出与重放。

证据冲突时，优先级为：

```text
live runtime > network traffic > served assets > process configuration > persisted artifacts > source
```

## 会话与状态

运行数据默认保存在 `~/.repi/agent`，与其他 Pi 配置隔离。会话自动保存，并支持 `/resume`、`/tree`、`/fork`、`/clone` 和 `/compact`。

长任务支持自动压缩、重试、pending writes、checkpoint 和进程重启恢复。工具缺失、目标不完整或证据不足时，REPI 会记录 blocker 和下一条可执行动作，而不是制造成功结果。

## 扩展与集成

REPI 提供 Interactive TUI、Print、JSON、RPC 和 SDK 接口，并兼容 Pi 扩展、skills、prompt templates 与 MCP。

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

参阅 [Extensions](packages/coding-agent/docs/extensions.md)、[Skills](packages/coding-agent/docs/skills.md)、[SDK](packages/coding-agent/docs/sdk.md) 和 [MCP](packages/coding-agent/docs/recon.md)。

## 参与开发

```bash
git clone https://github.com/multi-zhangyang/pi-recon-agent.git
cd pi-recon-agent
npm ci --ignore-scripts
npm run check
```

完整验证：

```bash
npm test
npm run smoke:repi -- --json
npm run smoke:install-path -- --json
npm run smoke:extensions -- --json
npm run smoke:release -- . --json
```

提交代码前请阅读 [CONTRIBUTING.md](CONTRIBUTING.md) 和 [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)。

## 发布

GitHub Release 提供同版本的 AI、Agent Core、TUI 和 Coding Agent tarball，以及包含文件大小、SHA-256 和安装命令的 `repi-release-manifest.json`。四个包必须使用同一版本并一起安装：

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
| [Quickstart](packages/coding-agent/docs/quickstart.md) | 安装、认证与首个会话 |
| [Usage](packages/coding-agent/docs/usage.md) | 交互模式和命令行 |
| [Providers](packages/coding-agent/docs/providers.md) | Provider、认证和模型接入 |
| [Runtime Configuration](docs/reverse-agent/repi-runtime-configuration.md) | `REPI_*` 和 `models.json` |
| [Agent Harness](packages/agent/docs/agent-harness.md) | Agent loop、session、compaction 与恢复 |
| [Security](SECURITY.md) | 安全策略与漏洞报告 |
| [Support](SUPPORT.md) | 自助诊断与问题反馈 |

## 安全

REPI 以当前用户权限读取文件、执行命令并调用模型服务。不要在公开 Issue、日志或截图中提交 API key、cookie、session、HAR、浏览器 profile、私有目标数据或 `~/.repi/agent/auth.json`。

安全漏洞请通过 GitHub Security Advisory 私密报告，流程见 [SECURITY.md](SECURITY.md)。

## License

[MIT](LICENSE)
