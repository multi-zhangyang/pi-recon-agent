# Pi-RECON mobile runtime task

任务：$ARGUMENTS

执行协议：

1. 先 `re_kernel build` 和 `re_map <apk-or-workspace>` 固化 execution kernel、APK/workspace map、hash、manifest、package hints。
2. 对 APK/Android/mobile reverse 目标调用 `re_mobile_runtime plan <apk-or-package> [packageName] [timeout-ms]`，生成 `mobile_runtime_artifact`、`device_matrix`、`apk_inventory`、`process_map`、`hook_plan`、`frida_hooks`、`native_trace`、`anti_debug_checks`、`replay_commands`、`capture_script` 和 `next_mobile_command`。
3. 需要动态证据时调用 `re_mobile_runtime run <apk-or-package> [packageName] [timeout-ms]`；默认只生成观测与 hook 模板，只有明确需要 live Frida attach 时设置 `PI_RECON_MOBILE_ATTACH=1`。
4. 把 Java crypto/String.equals、native strcmp/strncmp/memcmp/strstr、Debug.isDebuggerConnected、root/debug/emulator/Magisk/string sweep anchors 送入 `re_verifier matrix`、`re_compiler draft|final`、`re_knowledge_graph build`。
5. 输出集中证据块：artifact 路径、APK sha256、packageName、device/process/PID、Frida hook 文件、anti-debug/root anchors、复现命令和下一步。
