# REPI

REPI 是面向逆向、渗透测试、取证和安全研究任务的终端智能体。它在本机环境中调用真实工具，完成目标识别、任务拆解、执行验证、证据记录和结果复现。

```bash
curl -fsSL https://raw.githubusercontent.com/multi-zhangyang/pi-recon-agent/main/install.sh | bash
```

```bash
export REPI_AUTH_TOKEN="sk-xxxxx"
export REPI_BASE_URL="https://api.example.com/v1"
export REPI_MODEL="provider/model-id"
export REPI_MODEL_API="openai-compatible"   # openai-compatible | openai-responses | anthropic
export REPI_CONTEXT_WINDOW=262144
export REPI_AUTO_COMPACT_WINDOW=262144

repi doctor
repi model status
repi
```

## 特性

- **逆向与漏洞分析**：支持 native binary、pwn、firmware、mobile、malware、memory forensics、PCAP/DFIR、web/API、cloud/identity、crypto/stego 等任务类型。
- **真实工具链执行**：可调用 `gdb`、`radare2`、`tshark`、`binwalk`、`frida`、`pwntools`、`angr`、`z3`、`volatility3`、`yara`、`nmap`、`sqlmap` 等工具。
- **专家子代理**：内置 explorer、planner、operator、verifier、reverser，复杂任务可拆分给隔离 worker 执行。
- **证据闭环**：默认要求命令输出、artifact、PoC、复现步骤和验证结论，不把猜测当结果。
- **Goal Mode**：`/goal` 可启动长任务模式，footer 显示目标状态和 token 使用。
- **环境变量模型配置**：使用 `REPI_*` 变量快速切换 OpenAI-compatible、OpenAI Responses、Anthropic Messages 兼容接口。
- **扩展兼容**：支持 upstream pi 扩展生态，可安装 `pi-web-access` 等扩展。
- **独立运行目录**：命令为 `repi`，运行目录为 `~/.repi/agent`，不覆盖 `pi` 或 `~/.pi`。

## 系统要求

- Linux / macOS / WSL
- Node.js `>= 22.19.0`
- Git

推荐使用 `nvm` 安装 Node.js：

```bash
nvm install 22
nvm use 22
```

## 安装

### 一键安装

```bash
curl -fsSL https://raw.githubusercontent.com/multi-zhangyang/pi-recon-agent/main/install.sh | bash
```

安装完成后会把 `repi` 加入 PATH。若当前 shell 未刷新，执行安装器提示的命令，例如：

```bash
source ~/.bashrc
# 或
export PATH="$HOME/.local/bin:$PATH"
```

安装成功输出示例：

```text
INFO: Downloading REPI source into ~/.repi-src
■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■ 100%
INFO: Installing REPI launcher
■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■ 100%
INFO: Verifying offline startup
■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■ 100%

Successfully added repi to $PATH in ~/.bashrc

REPI 0.1.2 installed successfully, to start:

source ~/.bashrc  # Load new PATH (or open a new terminal)
cd <project>      # Open directory
repi              # Run command
```

### 从源码安装

```bash
git clone https://github.com/multi-zhangyang/pi-recon-agent.git
cd pi-recon-agent
bash install.sh
```

常用参数：

```bash
bash install.sh --prefix ~/.repi-src
bash install.sh --bin-dir ~/.local/bin
bash install.sh --branch main
bash install.sh --skip-npm
```

### 从 Release tarball 安装

从 [Releases](https://github.com/multi-zhangyang/pi-recon-agent/releases) 下载同版本 4 个包后一起安装：

```bash
npm install -g \
  pi-recon-repi-ai-0.1.2.tgz \
  pi-recon-repi-agent-core-0.1.2.tgz \
  pi-recon-repi-tui-0.1.2.tgz \
  pi-recon-repi-coding-agent-0.1.2.tgz

repi doctor
```

## 模型配置

REPI 默认使用 Claude Code 风格的环境变量配置模型。内置 provider catalog 默认关闭；常规使用只需要设置 `REPI_*`。

```bash
export REPI_AUTH_TOKEN="sk-xxxxx"
export REPI_BASE_URL="https://api.example.com/v1"
export REPI_PROVIDER="my-provider"           # 可选，footer/provider id，默认 repi-env
export REPI_MODEL="provider/model-id"
export REPI_MODEL_API="openai-compatible"
export REPI_CONTEXT_WINDOW=262144
export REPI_AUTO_COMPACT_WINDOW=262144
export REPI_MAX_TOKENS=16384
export REPI_SUBAGENT_MODEL="provider/worker-model"

repi model status
repi
```

`REPI_MODEL_API` 支持：

| 值 | 协议 |
|---|---|
| `openai-compatible` / `openai-completions` | OpenAI Chat Completions |
| `openai-responses` / `response` | OpenAI Responses |
| `anthropic` / `anthropic-messages` | Anthropic Messages |

示例：

```bash
export REPI_AUTH_TOKEN="sk-xxxxx"
export REPI_BASE_URL="https://api.morphllm.com/v1"
export REPI_PROVIDER="morph"
export REPI_MODEL="morph-glm52-744b"
export REPI_MODEL_API="openai-compatible"
export REPI_CONTEXT_WINDOW=262144
export REPI_AUTO_COMPACT_WINDOW=262144

repi model status
repi
```

检查模型解析：

```bash
repi --offline --list-models
repi model list
repi model doctor
repi model test
```

如需启用 upstream pi 的内置模型表：

```bash
export REPI_LOAD_BUILTIN_MODELS=1
```

## 常用命令

```bash
repi                              # 交互式启动
repi -p "分析 ./target"           # 一次性任务
repi --offline --help             # 离线帮助
repi doctor                       # 安装与运行环境检查
repi selfcheck --deep             # 深度自检和工具探测
repi smoke --json                 # 快速 smoke
repi bugreport --stdout           # 脱敏诊断报告
repi update                       # 更新当前安装
repi uninstall                    # 卸载预览
repi uninstall --apply            # 执行卸载
```

## Goal Mode

交互会话中使用：

```text
/goal --tokens 100k 完成目标描述
/goal status
/goal pause
/goal resume
/goal clear
```

完成条件由内置 `goal_complete` 工具确认；目标未完成时 footer 会持续显示当前状态。

## 逆向工具链

安装常用安全工具：

```bash
repi bootstrap
repi bootstrap --dry-run
repi bootstrap --only gdb,pwntools,binwalk,tshark
repi bootstrap --list
```

生成本机工具索引：

```bash
repi selfcheck --deep
```

## 子代理

可在任务中显式要求委派专家：

```bash
repi -p "委派 reverser 专家分析 ./vuln，生成 PoC 并给出复现证据"
```

子代理运行记录位于：

```text
~/.repi/agent/recon/agent-threads/
```

## 扩展

安装扩展：

```bash
repi install npm:pi-web-access
repi list
```

REPI 已内置 Goal Mode；安装 `@narumitw/pi-goal` 时会以内置实现为准，避免命令冲突。

```bash
repi install npm:@narumitw/pi-goal
```

## MCP

配置文件：

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
      "env": { "EXAMPLE_TOKEN": "$EXAMPLE_TOKEN" },
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
```

## 目录结构

```text
packages/coding-agent/      REPI CLI 和 agent runtime
packages/agent/             agent core
packages/ai/                LLM API runtime
packages/tui/               terminal UI
scripts/reverse-agent/      install / doctor / smoke / selfcheck / bootstrap
repi-profile/               默认 REPI profile
install.sh                  安装入口
```

## 本地验证

```bash
npm run check
npm run smoke:install-path -- --json
npm run smoke:release -- . --json
npm run smoke:extensions -- --json
```

## 隐私

不要提交 API key、cookie、session、HAR、浏览器 profile、`~/.repi/agent/auth.json` 或私有目标数据。

## License

MIT
