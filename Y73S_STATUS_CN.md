# Vivo Y73s 项目当前状态（唯一状态入口）

> 更新时间：2026-11-09  
> 当前分支：`y73s-cred-layout-guards-20261108`  
> 当前源码 HEAD：`b06048a867e802e566e0f79f6d0f8a7b6a59f74a`  
> 本文是当前状态的权威摘要；历史审计报告保留技术证据，若历史记录与本文冲突，以最新源码和 CI 为准。

## 1. 当前结论

本轮完成了 KPIMG 启动映射、LKM/KPM ELF 与 ARM64 重定位、凭据偏移保护、任务扩展身份校验及 Kbuild 条件参数优化。

- Y73S GCC 14.2 KPIMG 构建与专用审计：通过。
- Host kptools 构建及全量源码契约审计：通过。
- Windows kptools 构建：最新 HEAD 对应工作流已通过。
- 目标 Linux 4.14.141 的真实 `.ko` 编译、KPM 动态加载、设备启动和 APatch/root 验证：尚未完成。

**因此当前结论是源码与 KPIMG 构建阶段取得进展，不是设备可用或可刷入版本。**

## 2. 分支与最近 CI

- 分支：[y73s-cred-layout-guards-20261108](https://github.com/ljx-91/kptools-fix/tree/y73s-cred-layout-guards-20261108)
- 当前 HEAD：[b06048a](https://github.com/ljx-91/kptools-fix/commit/b06048a867e802e566e0f79f6d0f8a7b6a59f74a)

| 工作流 | Run | 结果 | 证明范围 |
|---|---:|---|---|
| Y73S Android KPIMG / GCC 14.2 | [42653184629](https://github.com/ljx-91/kptools-fix/actions/runs/42653184629) | 成功 | Y73S KPIMG 构建、栈帧与映射审计、打包 |
| Y73S host kptools + source contracts | [42653184913](https://github.com/ljx-91/kptools-fix/actions/runs/42653184913) | 成功 | Host 工具构建、12 项源码契约验证 |
| KernelPatch Windows Build | [42653184632](https://github.com/ljx-91/kptools-fix/actions/runs/42653184632) | 成功 | Android KPIMG 与 Windows kptools.exe 构建及打包 |

全量源码契约审计包含 bootimg I/O、kptools patch bounds、KPIMG loader、KPM lifecycle、LKM/KPM contract、ELF/RELA loader、Hook runtime、supercall input、userd file、Y73s fphook、memblock 和 runtime contract 检查。

这些是源码级和构建级证据，不替代目标 KDIR 编译、设备端加载或运行时压力测试。

## 3. 本轮完成的关键修复

### KPIMG / Y73s 启动映射

- 检查物理地址到线性映射地址、kimage 地址的加法溢出和搬迁范围。
- 把镜像复制拆到独立的有界复制 helper，处理未对齐 extra 区域及不足一个 64 位字的尾部。
- 保留 `_paging_init` 的固定 `0x130` 栈帧，避免破坏 `start` 尾部汇编的寄存器恢复协议。
- 最新 GCC 14.2 KPIMG 构建和栈帧审计通过。

### LKM / KPM ELF 与模块生命周期

- ELF 符号偏移、符号长度、节范围及地址加法溢出增加 fail-closed 检查。
- 修复可执行内存释放时传递模块大小的问题。
- 强化 RELA 元数据、符号索引、目标写入范围和失败回滚检查。
- 模块活动调用、Hook owner 引用和卸载状态继续由锁保护；活动引用未清空时不释放模块映像。

### ARM64 重定位：KPIMG 与 LKM 两条路径同步

- PREL16/PREL32 使用有符号溢出范围。
- signed MOVW 根据完整有符号值选择 MOVZ/MOVN，避免负值被截断后错误选择 MOVZ。
- ABS/PREL 数据重定位使用 `memcpy`，不再把合法的未对齐数据位置当作指令对齐错误。
- 指令重定位仍要求 4 字节对齐。
- 两条加载路径由源码契约脚本共同检查，避免只修 LKM 而遗漏 KPIMG。

### 凭据与任务扩展身份

- 凭据 capability 偏移在任何指针运算前验证；失败时走统一清理路径并恢复 current。
- task extension 槽位身份增加运行时解析的内核栈地址，并同时核对 PID/TGID，降低 task_struct 地址和 PID 被复用后误匹配旧权限状态的风险。
- 槽位仍不回收，避免破坏锁外读者持有的静态槽位指针。

### LKM Kbuild 参数

- BTI 参数仅在 `CONFIG_ARM64_BTI_KERNEL=y` 时启用。
- SCS workaround 仅在目标配置启用 SCS 时添加。
- 目标 Boot 的 .config 未发现上述 BTI/SCS 配置项，因此不再无条件把这些参数传给 Y73s 的 Clang 9.0.3 构建。
- Hook engine 的 CFI/LTO 隔离策略仍需结合精确目标 KDIR、真实编译命令和 CFI shadow ABI 进一步验证。

## 4. 仍未关闭的验证门槛

1. 获取与设备固件完全匹配的 Linux 4.14.141 内核源码/构建目录、生成头文件、`Module.symvers`、`.config` 和 Clang/LLD 9.0.3 工具链。
2. 使用目标 KDIR 真实编译 `kernelpatch.ko`，解决所有编译、链接、modpost 和 MODVERSIONS 问题。
3. 对 KPIMG/KPM ELF 与 RELA 输入执行畸形数据测试、边界测试和失败回滚测试。
4. 在可恢复的隔离内核环境中验证 Hook 安装/卸载、KPM load/unload、并发调用和 callback 生命周期。
5. 只有上述证据完整后，才制定单独的真机启动与 APatch 初始化验证方案。

## 5. 设备与操作安全边界

- 不使用 Fastboot。
- 不执行刷机、boot/vbmeta 修改或任何分区写入。
- 不把 KPIMG 构建成功、静态 patch 成功或源码契约通过解释为设备可启动。
- 不用 Android 12/Linux 5.10 通用 DDK 结果替代 Y73s Linux 4.14.141 的目标构建证明。

## 6. 文档索引与清理说明

- [原始 Boot 离线审计](Y73S_BOOT_OFFLINE_AUDIT_20261109.md)：Boot/DTB 布局、内核配置、AVB descriptor 与候选镜像复核。
- [Y73s 定向工具改动说明](OPTIMIZATION_Y73S_CN.md)：kptools 严格 Kallsyms、镜像布局、密钥日志处理及历史构建方法。
- [Allocator ABI 深度审计](Y73S_ALLOCATOR_DISPATCH_AUDIT.md)：memblock ABI 与映射路径历史证据。
- [Runtime failure 深度审计](Y73S_RUNTIME_FAILURE_AUDIT.md)：KPIMG 早期启动、映射、栈帧、Hook 和 relocation 历史证据。
- [Hook concurrency / LKM KPM 深度审计](Y73S_HOOK_CONCURRENCY_AUDIT.md)：Hook 生命周期、模块管理和 ELF/RELA 历史证据。
- [LKM 实现与验证边界](lkm/README.md)：LKM 架构、源码 CI 覆盖和目标 KDIR 要求。
- [历史只读构建记录](BUILD_VALIDATION_CN.md)：早期本机编译与 boot 只读解析数据，不是当前 CI 报告。

历史深度审计保留为证据，不再充当当前状态入口；已过时的阶段性判断以本文件和最新源码为准。没有确认无用的证据文件，本轮不做破坏性删除。
