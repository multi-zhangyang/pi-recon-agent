# 安全政策

REPI Agent 是本地运行的 autonomous coding agent，用于组织逆向工程、漏洞研究和渗透测试工作流。它会在当前用户权限下读取文件、执行命令、调用模型 provider，并把 evidence、session 和配置写入本机运行目录。

默认运行目录：

```text
~/.repi/agent
```

## 报告安全问题

如果你发现 REPI 或本仓库代码中的安全问题，请优先使用 GitHub Security Advisory 的私有报告入口。报告中请包含：

- 影响范围和安全边界。
- 复现步骤、PoC、日志或最小样例。
- 受影响版本、commit、平台和配置。
- 是否涉及 provider、auth、session、extension、package install 或 release artifact。
- 已知缓解方式。

不要在公开 Issue 中发布未脱敏的漏洞利用细节、API key、token、私有 baseUrl、auth.json、session 或 bugreport。

## 范围内

以下类型通常属于安全问题：

- REPI 自身代码导致的越权文件读写、命令执行或权限边界绕过。
- 安装、更新、package/binary 分发链路中的供应链风险。
- `bugreport`、model export 等诊断功能泄露本地密钥或私有端点。
- provider/auth/session 处理逻辑把用户凭据发送到非预期目标。
- release artifact、CI、打包脚本或 npm package 内容包含密钥、私有配置或错误入口。
- 可信边界外输入导致默认配置被静默污染，并跨 workspace/target/session 影响后续任务。

## 通常不在范围内

以下行为通常不作为 REPI 漏洞处理，除非能证明 REPI 自身突破了操作系统或用户授权边界：

- 用户明确让 agent 在本机执行命令、修改文件或安装工具。
- 用户安装并启用的第三方 extension、skill、prompt、package 的行为。
- 在不可信仓库中主动加载项目指令、脚本或配置造成的提示注入风险。
- 已经拥有当前用户文件写权限后，修改 `~/.repi/agent`、workspace、shell 配置或环境变量造成的行为变化。
- 用户故意把 API key、token 或私有 endpoint 写入公开文件。
- 恶意模型输出本身。
- 只依赖本地可信输入造成的资源消耗问题。

## 敏感数据处理

维护者和贡献者不得提交以下内容：

- API key、GitHub token、OAuth token、Authorization header。
- `~/.repi/agent/auth.json`、未脱敏 session、原始 bugreport。
- 私有 provider baseUrl、内部网关、客户目标信息。
- 未脱敏 evidence、PCAP、日志或截图。

如需分享诊断信息，请使用：

```bash
repi bugreport --stdout
```

再手工确认输出已经脱敏。

## 响应流程

维护者会根据影响面、可复现性和默认配置可达性评估优先级。修复完成后，会在 release note 或安全公告中说明受影响版本、修复版本和缓解步骤。
