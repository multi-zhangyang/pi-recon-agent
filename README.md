# REPI Reverse/Pentest Agent

REPI 是独立的逆向渗透命令行智能体,主题是 reverse / pentest **execution**:逆向工程、漏洞利用与验证、Web/API 渗透、pwn、移动、固件、流量/取证、恶意样本分析,以及可复现证据整理。它提供独立的 `repi` 命令、独立运行目录、可配置模型、多工具调用、MCP 接入、上下文压缩、任务记忆、**专家子代理委派**和工程化诊断能力。

REPI 与原版 `pi` agent 划开边界:它不是 `pi` 的 profile,也不是通用 coding agent。项目复用成熟的工具调用、插件、MCP 和 subagent 机制,不回到纯自研 agent 控制平面的臃肿。安装 REPI 不会覆盖本机已有的 `pi` 命令,运行数据默认写入 `~/.repi/agent`。

> 版本:`0.78.1-repi.1` · 仓库:`https://github.com/multi-zhangyang/pi-recon-agent`(fork 自 `earendil-works/pi`)

---

## 核心能力

### 专家子代理委派(specialist delegation)

REPI 内置 5 个进程隔离的专家子代理,host agent 可通过 `re_subagent` 工具把硬目标委派给真正有方法论的专家,而不是自己一把梭:

| spec | 定位 | thinking | tools |
|---|---|---|---|
| `reverser` | 原生二进制 / pwn / 固件 / 恶意样本 / 内存取证 | `xhigh` | read/grep/find/ls/bash/write/edit |
| `verifier` | 证伪优先的验证(≥2 次稳定复现 + 无反证才判 proved) | `high` | +write |
| `explorer` | 只读 mapping / 资产面 / 路由枚举 | `low` | read/grep/find/ls/bash |
| `planner` | 把模糊目标转成可证伪的 lane 计划,不执行 | `medium` | +write |
| `operator` | 有界执行 / 跑命令 / 落地操作 | `low` | +write |

每个专家都带结构化 doctrine(reverser 的 RE 方法论覆盖 mitigation triage → 静态 → 动态 → primitive→exploit,以及固件 binwalk/unblob、恶意样本 yara/capa/floss、内存取证 volatility3、angr/z3 符号求解),而非一句空话。

**文件化 handoff(关键设计):** reasoning 模型常把最终总结放进 thinking block,transport 不回传,导致父代理拿到空 handoff、委派白跑。REPI 的解法是**通用**的(不写 reasoning_content 适配器、不做 per-provider 特殊分支):子代理被强制把完整 handoff 写到 `$REPI_WORKER_HANDOFF_PATH` 文件,`mergeRun` 把该文件作为 `## Worker handoff` 段回传父代理 —— 即使最终文本被丢,发现也不丢。

**Completion gate:** reverser doctrine 硬性禁止"我看一眼 disasm 就知道答案"的捷径。pwn/exploit 任务只有当 PoC artifact 真的写盘、真的跑出输出、且 handoff 文件存在时才算完成。静态分析是 triage,不是 Outcome。

**Phase 0 工具自适应:** reverser 先探测工具是否存在,缺失时走通用 fallback,绝不卡在"工具没装":checksec→`readelf -lW/-dW`、gdb→`strace -f`/`objdump -d`、binwalk→`dd`+`strings`+手工 magic、ROPgadget/ropper→`objdump -d | grep` 手挑、pwntools→`python3`+`socket`/`struct`、angr/z3→手工约束、volatility3→手工 strings/carve、yara/capa/floss→`strings -n 6`+手工规则、upx→copy+`upx -d`。工具贫乏的 env 也能干活。

### 路由感知的默认流程

默认就走真实强路径(不是机械 regex / 假 swarm):

- `re_autopilot` 默认 `reasoning=llm`、`dispatch=specialist`(按 lane→spec 映射自动派真实专家)
- `re_swarm` 默认 `execution=real`(真实隔离 worker 进程)
- per-turn 作用域记忆默认开启

设 `REPI_AUTOMODE_LEGACY=1` 可回退到旧的 regex/inline/simulated 默认。所有真实路径都 cwd-gated 且递归封闭(子代理内不再派孙),ctx-less 调用和 worker 线程自动回退,测试基线不受影响。

### 路由 / 工具面

- **18 个 reverse/pentest domain 路由**(CTF/sandbox、Native reverse、Pwn、Firmware/IoT、Malware、Memory forensics、Web/API、Cloud、Identity、Mobile/iOS、Mobile/Android、Crypto/stego、DFIR、PCAP、agentsec、Web scanning 等),`routeRepiTask` 为每个 domain 给出具体 workflow。
- **40+ `re_*` 工具**:re_subagent / re_reason(PTT 快照 + planner 子代理)/ re_challenge(对抗式验证)/ re_supervisor(LLM critique)/ re_autopilot / re_swarm / re_mission / re_map / re_evidence / re_graph / re_exploit_chain / re_proof_loop / re_tool_index / re_toolchain_domain 等,组成 route→map→lane→run→evidence→verify 执行链。

### 其他特性

- **独立命令**:`repi` 启动,不覆盖用户已有的 `pi`。
- **模型配置**:OpenAI Chat Completions / Responses / Anthropic Messages 兼容,自定义 base URL、上下文窗口、价格、缓存价格、默认模型。
- **上下文管理**:自动 compact、resume contract、跨会话恢复。
- **MCP**:stdio / streamable HTTP,工具搜索、proxy 调用、resources、prompts、连接池、失败重连、输出脱敏。
- **记忆治理**:作用域隔离、沉淀、查询、清理、修复、导出,避免跨任务污染。
- **诊断**:`doctor` / `smoke` / `selfcheck` / `bugreport`。

---

## 安装

### 从源码安装

```bash
git clone https://github.com/multi-zhangyang/pi-recon-agent.git
cd pi-recon-agent
npm install
npm run install:repi
```

安装后检查:

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

### (可选)装配逆向工具链

REPI 的 reverser 在工具贫乏时也能用 fallback 干活,但装上真实工具效果更好。可按需安装:

```bash
# Debian/Ubuntu 示例
apt-get install -y gdb binwalk file radare2 yara
pip install --user --break-system-packages pwntools ROPgadget ropper capa floss angr z3-solver
# volatility3 / ghidra / burpsuite / wireshark 按各自方式安装
```

`repi selfcheck --deep` 会探测本机可用工具并写 `~/.repi/agent/recon/tools/tool-index.md`。

---

## 常用命令

```bash
repi                              # 交互式启动
repi -p "分析 /tmp/vuln 的溢出"   # 非交互一次性任务
repi --offline --help             # 查看帮助,不调用模型
repi doctor                       # 检查安装/配置/权限/常见问题
repi smoke --json                 # 本地快速 smoke
repi selfcheck --deep             # 更完整的本机自检(含工具探测)
repi bugreport --stdout           # 生成脱敏诊断信息
```

### 委派一个 reverser 专家

在交互会话里,host agent 会自己判断何时调用 `re_subagent`;也可在 `-p` 任务里直接要求委派:

```bash
repi -p "用 re_subagent 派 reverser 专家对 /tmp/vuln 做完整 pwn:checksec、算溢出偏移、建 pwntools PoC、本地证明 ≥2 次起 shell,把 handoff 写文件"
```

子代理完成后,父代理会拿到 `## Worker handoff`(offset / 地址 / PoC 路径 / 真实捕获输出)。查看子代理 run root:

```bash
ls -R ~/.repi/agent/recon/agent-threads/<run-id>
cat ~/.repi/agent/recon/agent-threads/<run-id>/handoff.md
```

### swarm / autopilot

```bash
repi swarm plan ./target --workers 4
repi swarm run ./target --workers 4
repi swarm status
repi swarm merge <run-id>
```

`re_autopilot` 工具支持 `dispatch=inline|specialist`(默认 specialist);`re_swarm` 支持 `execution=simulated|real`(默认 real)。

---

## 模型配置

配置文件:

```text
~/.repi/agent/models.json
~/.repi/agent/auth.json
```

推荐通过命令写入本地配置,不要把密钥写进仓库:

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
          "cost": { "input": 2, "output": 8, "cacheRead": 0.5, "cacheWrite": 2 }
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
      "models": { "o4-mini": { "contextWindow": 200000, "maxTokens": 8192, "reasoning": true } }
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
      "models": { "claude-sonnet-4": { "contextWindow": 200000, "maxTokens": 8192, "reasoning": true } }
    }
  }
}
```

查看与诊断:

```bash
repi model list
repi model doctor
repi model cost my-openai/gpt-4.1 --input 100000 --output 8000
```

> 长跑子代理提示:reverser 做完整 pwn 可能跑数分钟。host 的 print 模式默认自超时 210s,若委派 `timeoutMs` 更长,需抬高 host 的 `REPI_PRINT_TIMEOUT_MS`(例如 `REPI_PRINT_TIMEOUT_MS=660000`)使其高于子代理超时。

---

## MCP 配置

配置文件:

```text
~/.repi/agent/mcp.json
<project>/.repi/mcp.json
```

示例:

```json
{
  "mcpServers": {
    "browser-tools": {
      "transport": "stdio",
      "command": "npx",
      "args": ["-y", "some-mcp-server"],
      "env": { "EXAMPLE_TOKEN": "$EXAMPLE_TOKEN" },
      "autoRegisterTools": true,
      "deferToolSchemas": true,
      "timeoutMs": 30000,
      "poolIdleMs": 15000
    },
    "remote-tools": {
      "transport": "http",
      "url": "https://mcp.example.com/mcp",
      "headers": { "Authorization": "Bearer $MCP_API_KEY" },
      "autoRegisterTools": true,
      "deferToolSchemas": true
    }
  }
}
```

常用命令:

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

对 search/router 模式 MCP:`mcp__server__call.tool` 必须填 MCP 当前 `tools/list` 真实暴露的工具名。若搜索结果提示 `call_tool({ name: "browser_status", args: {} })`,则 proxy 参数应为:

```json
{ "tool": "call_tool", "arguments": { "name": "browser_status", "args": {} } }
```

REPI 复用 MCP session,并在 stdio wrapper 关闭时清理整个进程组,避免 `xvfb-run`、`npm exec`、浏览器 wrapper 这类子进程残留。

---

## 上下文压缩

配置文件 `~/.repi/agent/settings.json`:

```json
{
  "compaction": { "enabled": true, "triggerPercent": 85, "autoResume": true }
}
```

交互界面可用 `/context`、`/compact` 查看当前上下文状态。

---

## 记忆管理

```bash
repi memory status
repi memory list
repi memory show <id>
repi memory why <query>
repi memory purge --dry-run
repi memory repair --dry-run
```

默认策略是作用域隔离:项目/目标/任务不匹配的记忆不会主动注入,避免旧任务污染新任务。per-turn 作用域记忆默认开启,设 `REPI_PER_TURN_MEMORY=0` 可关闭。

---

## 开发检查

普通开发只需要:

```bash
npm run check
node scripts/reverse-agent/repi-smoke.mjs . --json
```

这些检查不依赖私有模型、不要求外部凭据、不访问真实目标,也不依赖某个特定 MCP。

针对委派/推理层的单测(stub binary,无真实 provider):

```bash
node packages/coding-agent/node_modules/vitest/dist/cli.js \
  --root packages/coding-agent --run \
  test/suite/re-subagent-tool.test.ts test/suite/re-reason-tool.test.ts
```

架构约束(单向依赖):`packages/coding-agent/src/core/repi/*` 不得导入 `recon-profile.ts`;REPI 不得做 per-provider 特殊分支或 reasoning-content 适配器。`npm run contract:repi` 会校验这些契约。

---

## 目录

```text
packages/coding-agent/      REPI CLI 和核心 agent runtime
  src/core/repi/            REPI 主线模块(memory/mission/routes/toolchain/profile/...)
  src/core/agent-thread-manager.ts  专家子代理管理器(5 builtin spec + 文件 handoff)
  src/core/recon-profile.ts REPI reverse/pentest kernel profile(装配层)
packages/agent-core/        agent core types/runtime
packages/tui/               终端 UI
scripts/reverse-agent/      安装、诊断、smoke、selfcheck、product contract 脚本
repi-profile/               默认 REPI profile、prompt、配置说明
docs/                       使用文档和设计说明
```

---

## 隐私与配置

- 不要提交 `~/.repi/agent/auth.json`、真实 API key、私有 base URL、cookie、session、HAR、浏览器 profile。
- 文档和示例只使用占位符。
- `repi bugreport` 默认做脱敏处理,适合提交 issue 前检查。

## License

见仓库许可证文件。
