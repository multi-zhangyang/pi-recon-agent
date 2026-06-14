# REPI Reverse Agent Docs

本目录只保留 REPI 的普通使用和运行时说明。通用验证入口是：

```bash
npm run check
node scripts/reverse-agent/repi-smoke.mjs . --json
```

核心文档：

- `model-provider-formats.md`：模型 provider、价格、缓存和兼容接口配置。
- `repi-runtime-configuration.md`：运行时配置、compact、profile、模型与诊断。

REPI 的原则是：按正常安装、正常模型配置、正常 `repi` 命令运行；不要依赖某台机器、某个私有 provider、某个特定 MCP 或一批特制测试脚本。
