# 支持与反馈

## 自助诊断

遇到安装、配置或运行问题时，先执行：

```bash
repi doctor
repi smoke
repi model doctor
```

需要导出诊断时：

```bash
repi bugreport --stdout
```

提交前请确认输出中没有 API key、token、私有 baseUrl、auth.json、session 或未脱敏目标信息。

## 提交问题

请使用 GitHub Issue 模板，并提供：

- REPI 版本和安装方式。
- 操作系统、Node.js 版本。
- 复现命令和关键日志。
- `repi doctor` / `repi smoke` 结果。

## 安全问题

安全问题请看 [SECURITY.md](SECURITY.md)，不要在公开 Issue 中发布敏感细节。
