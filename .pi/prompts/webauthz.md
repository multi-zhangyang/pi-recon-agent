# Pi-RECON web authz task

任务：$ARGUMENTS

执行协议：

1. 先 `re_kernel build`、`re_map <url-or-project>`、必要时 `re_live_browser run <url>` 固化 routes、requests、storage、auth/session baseline。
2. 调用 `re_web_authz_state plan <url> [timeout-ms]`，生成 `web_authz_artifact`、`route_inventory`、`principal_matrix`、`object_probes`、`state_machine`、`sequence_replay`、`ownership_checks`、`rollback_checks`、`replay_commands`、`capture_script` 和 `next_web_authz_command`。
3. 需要动态证据时调用 `re_web_authz_state run <url> [timeout-ms]`；设置 `COOKIE_A/COOKIE_B` 或 `AUTH_A/AUTH_B` 区分主体，设置 `PI_RECON_OBJECT_A/PI_RECON_OBJECT_B` 做 IDOR/BOLA 对照。
4. 变更型 rollback 默认关闭；只有明确需要时设置 `PI_RECON_AUTHZ_MUTATE=1`、`PI_RECON_MUTATION_URL`、`PI_RECON_MUTATION_BODY`、`PI_RECON_RESTORE_BODY`。
5. 把 principal status/body-hash matrix、object ownership、sequence replay、rollback anchors 送入 `re_verifier matrix`、`re_compiler draft|final`、`re_replayer run`、`re_knowledge_graph build`。
