---
description: 启动 Pi-RECON Cloud/K8s identity 与权限边工作流
argument-hint: "<workspace-or-context>"
---
Pi-RECON Cloud/K8s task: $ARGUMENTS

必须执行：
1. 路由到 Cloud / container，并确认当前 lane：identity → runtime-config → metadata → privilege → report。
2. 运行 `cloud-identity-config-map`，记录 env/profile/KUBECONFIG/serviceaccount 的 len/hash/path，不输出 secret 原文。
3. 运行 `cloud-runtime-config-scaffold`，收集 Docker/K8s/IaC/云 CLI runtime config 与 RBAC/resource anchors。
4. 运行 `cloud-metadata-probe-scaffold`，用短超时验证 AWS/GCP/Azure metadata identity 可达性，保留 status/bytes/hash/token_len。
5. 运行 `cloud-privilege-edge-scaffold`，从 IAM/K8s manifest、env、serviceaccount 中定位最小 privilege edge。
6. 输出 Cloud identity anchors、Cloud/K8s runtime config anchors、Cloud metadata probe anchors、Cloud privilege edge anchors。
7. 给出 cloud-identity-rerun、cloud-runtime-config-rerun、cloud-metadata-probe-rerun、cloud-privilege-report-scaffold 或等价复现命令。
