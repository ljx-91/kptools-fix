# KernelPatch 0.13.10（Vivo Y73s 定向源码分支）

本目录是基于完整 KernelPatch 0.13.9 源码移植的定向优化分支。请先阅读 [OPTIMIZATION_Y73S_CN.md](OPTIMIZATION_Y73S_CN.md) 了解改动、Windows 编译方式和验证边界。

重点改动：严格 Kallsyms 候选验证、ARM64 vectors/CFI `pid_vnr` 检查、镜像 `image_size` 布局修正、boot 镜像输出长度修正，以及密钥日志脱敏和 FD 输入。

**注意：** 这是实验性源码，不是上游官方发布版，也没有实机启动成功保证。严格 Kallsyms 检查通过不代表 KPIMG 的启动兼容性已通过。
