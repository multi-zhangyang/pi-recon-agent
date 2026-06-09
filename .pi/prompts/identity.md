---
description: 启动 Pi-RECON Identity/AD graph 与凭据可用性工作流
argument-hint: "<domain/dc/target>"
---
Pi-RECON Identity/AD task: $ARGUMENTS

必须执行：
1. 路由到 Identity / Windows / AD，并确认当前 lane：principals → credentials → graph → pivot-proof → report。
2. 运行 `identity-ad-principal-enum-scaffold`，整理 DOMAIN/DC_IP/LDAP_URL/TARGET、Kerberos ticket、LDAP principal/SPN/group anchors。
3. 运行 `identity-ad-credential-usability-scaffold`，用受控 env 验证 password/hash/ticket 可用性，保留 exact status，不扩大横向。
4. 运行 `identity-ad-graph-scaffold`，汇总 BloodHound/Certipy/ADCS artifacts，定位最小 graph edge。
5. 输出 Identity/AD principal anchors、Identity/AD credential usability anchors、Identity/AD graph edge anchors。
6. 给出 identity-ad-enum-rerun、identity-ad-credential-check-rerun、identity-ad-graph-rerun、identity-ad-report-scaffold 或等价复现命令。
