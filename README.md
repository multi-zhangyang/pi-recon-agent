<p align="center">
  <a href="https://github.com/multi-zhangyang/pi-recon-agent">
    <img src="packages/coding-agent/docs/images/repi-logo.svg" width="132" alt="REPI">
  </a>
</p>

<h1 align="center">REPI</h1>

<p align="center">
  面向逆向工程、渗透测试与数字取证的终端智能体
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
  <a href="#工作方式">工作方式</a> ·
  <a href="#文档">文档</a> ·
  <a href="#参与开发">参与开发</a>
</p>

---

REPI 将大模型的分析能力与本地安全工具链连接起来，在一个持续会话中完成目标识别、任务规划、工具执行、证据归档和结果复现。它适合需要真实运行环境、长任务状态和可核验证据的安全研究工作，而不只是生成分析建议。

REPI 运行在当前工作目录，提供交互式终端、一次性命令、RPC 接口、MCP 服务与扩展机制。模型、凭据、会话和证据保存在独立的 `~/.repi/agent` 目录，不占用其他 Pi 配置。

## 核心能力

| 领域 | 能力 |
| --- | --- |
| Native / Pwn | ELF、PE、Mach-O、保护机制、调试、崩溃分析、ROP 与 PoC 复现 |
| Web / API | 路由与状态发现、浏览器/CDP、认证授权分析、请求重放与验证矩阵 |
| Mobile | APK 分析、ADB、Frida、Java/Native Hook、反调试与运行时取证 |
| Firmware / IoT | 固件识别、文件系统提取、服务枚举、二进制分析与攻击面映射 |
| DFIR / Malware | PCAP、内存取证、时间线、IOC、YARA、静态与动态行为分析 |
| Crypto / Stego | 编码与变换链识别、参数恢复、约束求解、签名与结果校验 |
| Cloud / Identity | Token 流、凭据有效性、权限边界、身份链路与部署状态验证 |

- **真实工具执行**：直接调用本机命令、调试器、反编译器、浏览器和分析框架。
- **证据优先**：结论关联命令输出、artifact、哈希、PoC、negative control 与 replay。
- **专业任务路由**：根据目标选择 lane、runtime 和工具链，避免一个通用 prompt 处理所有领域。
- **长任务运行时**：Goal Mode 提供预算、checkpoint、恢复、压缩和明确的完成条件。
- **有界多智能体**：worker 使用 claim、lease、retry、artifact 和 supervisor review 协作。
- **可扩展基础设施**：支持 MCP、skills、prompt templates、主题及 Pi 扩展生态。

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

安装器会构建运行时、安装 `repi` 命令并执行离线启动检查。首次加入 PATH 时会输出：

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

REPI 支持 OpenAI Chat Completions、OpenAI Responses 和 Anthropic Messages 协议。使用 Claude Code 风格的环境变量即可接入兼容服务：

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

持久化多个 provider、模型元数据、自定义请求头和价格时，使用 `~/.repi/agent/models.json`。完整格式见[模型运行时配置](docs/reverse-agent/repi-runtime-configuration.md)。

### 开始任务

```bash
cd /path/to/target
repi
```

直接输入任务，或启动带预算的长任务：

```text
/goal --tokens 100k 分析目标，定位可利用路径，并生成可复现证据
```

一次性调用和会话恢复：

```bash
repi -p "分析 ./target 并输出证据与复现步骤"
repi -c
repi -r
```

常用入口：

| 操作 | 命令 |
| --- | --- |
| 检查环境 | `repi doctor` |
| 检查模型 | `repi model doctor` |
| 查看任务 | `repi mission status` |
| 建立工具索引 | `repi bootstrap` |
| 导出诊断信息 | `repi bugreport --stdout` |
| 查看 MCP 服务 | `repi mcp status` |

## 工作方式

REPI 以可验证的执行闭环推进任务：

```text
Target -> Mission -> Map -> Specialist -> Runtime -> Evidence -> Verification -> Replay
```

| 层 | 职责 |
| --- | --- |
| Mission | 固化目标、范围、完成条件和当前 checkpoint |
| Map | 被动识别目标、环境、入口、依赖和可用工具 |
| Specialist | 为不同安全领域选择方法、工具和证据要求 |
| Runtime | 执行本机工具、浏览器、调试器或隔离 worker |
| Evidence | 记录命令、输出、artifact、哈希和结论关系 |
| Verifier | 复核关键声明，运行 negative control 和完成门禁 |
| Replay | 从已记录的输入与步骤重新验证结果 |

证据判断遵循运行时优先原则：

```text
live runtime > network traffic > served assets > process configuration > persisted artifacts > source
```

目标不完整、工具缺失或证据不足时，REPI 会保留 blocker 和下一条可执行动作，不会把推测标记为已验证结果。

## 模型与扩展

模型可来自当前进程的 `REPI_*` 环境变量、`~/.repi/agent/models.json` 或扩展动态注册的 provider。凭据可以引用环境变量，无需写入项目文件。

安装兼容扩展：

```bash
repi install npm:pi-web-access
repi list
```

MCP 配置位于 `~/.repi/agent/mcp.json` 或项目内的 `.repi/mcp.json`：

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

更多用法见 [Extensions](packages/coding-agent/docs/extensions.md)、[MCP](packages/coding-agent/docs/recon.md) 和 [Skills](packages/coding-agent/docs/skills.md)。

## 文档

| 文档 | 内容 |
| --- | --- |
| [Quickstart](packages/coding-agent/docs/quickstart.md) | 安装、认证、首个会话与常用操作 |
| [Usage](packages/coding-agent/docs/usage.md) | 交互模式、命令行和会话管理 |
| [Providers](packages/coding-agent/docs/providers.md) | Provider、认证与模型接入 |
| [Runtime Configuration](docs/reverse-agent/repi-runtime-configuration.md) | `REPI_*`、`models.json` 与协议兼容配置 |
| [Agent Harness](packages/agent/docs/agent-harness.md) | Agent loop、session、compaction 与 harness |
| [SDK](packages/coding-agent/docs/sdk.md) | 嵌入式与程序化调用 |
| [Extensions](packages/coding-agent/docs/extensions.md) | 扩展 API、工具、命令和 UI |
| [Security](SECURITY.md) | 漏洞报告与安全策略 |
| [Support](SUPPORT.md) | 支持渠道和问题反馈 |

## 参与开发

```bash
git clone https://github.com/multi-zhangyang/pi-recon-agent.git
cd pi-recon-agent
npm ci --ignore-scripts
npm run check
```

运行产品 smoke：

```bash
npm run smoke:repi -- --json
npm run smoke:install-path -- --json
npm run smoke:extensions -- --json
npm run smoke:release -- . --json
```

仓库由四个运行时包和一组产品脚本组成：

```text
packages/coding-agent/   CLI、交互界面、REPI runtime 与 SDK
packages/agent/          agent loop、harness、session 与 compaction
packages/ai/             provider、协议、流式响应与模型运行时
packages/tui/            terminal UI 组件与渲染基础设施
scripts/reverse-agent/   安装、诊断、smoke、契约与 release 工具
```

提交代码前请阅读 [CONTRIBUTING.md](CONTRIBUTING.md) 和 [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)。CI 会检查格式、类型、依赖锁定、provider payload、agent runtime、构建入口、安装路径、扩展兼容性和生产依赖漏洞。

## 发布包

每个 GitHub Release 提供同版本的 AI、Agent Core、TUI 和 Coding Agent tarball，以及包含文件大小、SHA-256 和安装命令的 `repi-release-manifest.json`。四个包需要一起安装：

```bash
npm install -g \
  pi-recon-repi-ai-<version>.tgz \
  pi-recon-repi-agent-core-<version>.tgz \
  pi-recon-repi-tui-<version>.tgz \
  pi-recon-repi-coding-agent-<version>.tgz
```

## 安全

请勿在公开 Issue 中提交 API key、cookie、session、HAR、浏览器 profile、私有目标数据或 `~/.repi/agent/auth.json`。安全问题请按照 [SECURITY.md](SECURITY.md) 中的私密报告流程提交。

## License

[MIT](LICENSE)
