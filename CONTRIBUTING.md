# 贡献指南

感谢你考虑为 REPI Agent 贡献代码、文档或问题报告。这个项目的维护原则是：**每一个变更都必须可复现、可验证、可回滚**。

## 提交 Issue

请优先使用 GitHub Issue 模板，并提供：

- REPI 版本、安装方式、操作系统和 Node.js 版本。
- 最小复现命令、关键日志、期望行为与实际行为。
- 是否涉及模型 provider、`~/.repi/agent/models.json`、`auth.json`、memory、swarm 或 compact。

不要在 Issue、PR、日志或截图里提交 API key、GitHub token、Authorization header、私有 baseUrl、会话文件或未脱敏的 bugreport。

## 提交 PR 前

1. 从最新 `main` 分支创建 feature branch。
2. 保持变更范围清晰，避免把重构、格式化和功能修改混在一个 PR。
3. 给出验证命令和结果；涉及 REPI harness 的变更必须说明新增或更新的 gate。
4. 不要提交本地运行态：`~/.repi`、`.repi/`、`auth.json`、session、bugreport、provider 私钥、模型密钥。

推荐本地验证：

```bash
npm install
npm run check
npm run smoke:repi
npm run gate:repi-harness
```

如果改了安装、入口、发布、文档或安全边界，还需要运行：

```bash
npm run gate:open-source-readiness
npm run build
```

## 代码规范

- TypeScript / JavaScript 代码必须通过 `npm run check`。
- 新增 runtime 行为要有可执行验证：script、gate、fixture、schema 或 smoke test。
- 任何能力声明都要绑定证据；不要只改 README 或 prompt。
- 面向用户的命令必须在 `README.md`、`--help`、doctor/smoke/harness 中保持一致。
- 对 provider、memory、bugreport、session、auth 的改动必须默认脱敏并保持本地私有。

## 文档规范

文档应该回答三个问题：

1. 怎么安装和更新。
2. 怎么配置模型并验证。
3. 出问题时怎么自检、导出脱敏诊断、恢复到可用状态。

新增文档要尽量给可复制命令，少写抽象口号。

## AI 辅助贡献

可以使用 AI/agent 辅助开发，但提交者必须理解并负责最终代码。请在 PR 中说明：

- 变更目标。
- 关键实现点。
- 本地验证结果。
- 已知风险或未覆盖项。

## 维护者合并标准

PR 合并前至少满足：

- 代码和文档没有明显过期名称、私有端点或密钥。
- CI 通过。
- 变更有明确证据链和回滚路径。
- 不降低 REPI 的独立产品边界、profile 隔离、memory 污染防护和 release harness 约束。
