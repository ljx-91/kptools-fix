# KernelPatch / APatch — Vivo Y73s 定向实验分支

本分支包含 Vivo Y73s（MTK / Android 10 / Linux 4.14.141）定向的 KPIMG 与 LKM/KPM 源码审计和修复。

**请先阅读唯一状态入口：[Y73S_STATUS_CN.md](Y73S_STATUS_CN.md)。** 当前 CI 结果、已完成修复、未关闭验证门槛和安全边界均以该文件为准。

主要技术记录：
- [kptools 定向改动说明](OPTIMIZATION_Y73S_CN.md)
- [Allocator ABI 深度审计](Y73S_ALLOCATOR_DISPATCH_AUDIT.md)
- [KPIMG runtime failure 深度审计](Y73S_RUNTIME_FAILURE_AUDIT.md)
- [Hook concurrency / LKM KPM 深度审计](Y73S_HOOK_CONCURRENCY_AUDIT.md)
- [LKM 架构与验证限制](lkm/README.md)

## 重要限制

- 当前主机工具、Y73s KPIMG 构建和 LKM 源码契约审计的 CI 已通过；这不代表 LKM 已针对 Y73s Linux 4.14.141 目标 KDIR 编译。
- 尚无真机启动、APatch 初始化或 root 验证结论。
- KPIMG 构建产物不是已认证可刷入镜像；不得仅凭 CI 通过就刷入设备。
- 本项目当前工作不使用 Fastboot，不修改 boot/vbmeta，不写入设备分区。
