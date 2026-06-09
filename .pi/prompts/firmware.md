---
description: 启动 Pi-RECON Firmware/IoT rootfs 逆向渗透工作流
argument-hint: "<firmware.bin|rootfs>"
---
Pi-RECON firmware/IoT task: $ARGUMENTS

必须执行：
1. 路由到 `Firmware / IoT`，确认 lanes：inventory → extract → filesystem → services → emulate → report。
2. 运行 `firmware-static-fingerprint-scaffold`，记录 hash/magic/entropy/binwalk/rootfs/arch/service hints。
3. 运行 `firmware-extract-rootfs-scaffold`，用 binwalk/unblob/unsquashfs/UBI fallback 提取 rootfs、kernel、web 和配置 artifacts。
4. 运行 `firmware-filesystem-config-secret-scaffold`，提取 passwd/shadow/key/NVRAM/config/default credential/web artifacts。
5. 运行 `firmware-service-surface-scaffold`，枚举 init、httpd/uhttpd/boa/lighttpd、dropbear/telnetd、CGI/API endpoints。
6. 运行 `firmware-emulation-scaffold`，生成 QEMU/chroot/service smoke 复现路径。
7. 输出 `Firmware image metadata anchors`、`Firmware extraction/rootfs anchors`、`Firmware config/secret anchors`、`Firmware service/web surface anchors`、`Firmware emulation/runtime anchors`。
8. 给出 `firmware-extract-rerun`、`firmware-config-secret-rerun`、`firmware-service-surface-rerun`、`firmware-emulation-scaffold-rerun`、`firmware-report-scaffold` 或等价复现命令。
