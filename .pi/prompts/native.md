# Pi-RECON native runtime task

任务：$ARGUMENTS

执行协议：

1. 先 `re_kernel build` 和 `re_map <elf-or-workspace>` 固化 execution kernel、ELF/workspace map、hash、loader、binary candidates。
2. 对 ELF/SO/Pwn/native reverse 目标调用 `re_native_runtime plan <elf-or-so> [timeout-ms]`，生成 `native_runtime_artifact`、`binary_inventory`、`mitigation_matrix`、`loader_libc`、`symbol_map`、`crash_plan`、`gdb_trace`、`breakpoint_plan`、`exploit_scaffold`、`replay_commands`、`capture_script` 和 `next_native_command`。
3. 需要动态证据时调用 `re_native_runtime run <elf-or-so> [timeout-ms]`；默认只生成观测与 GDB/pwntools 模板，只有明确需要 live GDB execution 时设置 `PI_RECON_NATIVE_RUN=1`，可用 `PI_RECON_NATIVE_ARGS` 传入参数。
4. 把 checksec/readelf/ldd/symbol/string、GDB breakpoint、SIGSEGV、RIP/EIP/RSP/ESP、cyclic offset、loader/libc anchors 送入 `re_verifier matrix`、`re_compiler draft|final`、`re_exploit_lab plan|run`、`re_knowledge_graph build`。
5. 输出集中证据块：artifact 路径、ELF sha256、mitigations、loader/libc、breakpoint/GDB trace、crash/register anchors、pwntools scaffold、复现命令和下一步。
