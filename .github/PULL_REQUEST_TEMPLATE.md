## 变更摘要

-

## 影响范围

- [ ] CLI / 安装 / 发布
- [ ] Provider / 模型配置
- [ ] Memory / Compact / Resume
- [ ] Swarm / 子代理 / 调度
- [ ] Harness / Gate / CI
- [ ] Docs only

## 验证

请粘贴实际执行结果：

```bash
npm run check
npm run smoke:repi
npm run gate:repi-harness
```

如涉及开源发布、入口、安装或文档：

```bash
npm run gate:open-source-readiness
npm run build
```

## 安全与隐私

- [ ] 没有提交 API key、token、Authorization header、私有 baseUrl、auth.json 或未脱敏 session。
- [ ] 没有把本地 `~/.repi`、`.repi/`、bugreport 或 runtime evidence 作为源码提交。
- [ ] 文档、help、doctor、harness 的用户命令保持一致。

## 备注
