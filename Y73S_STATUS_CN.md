# Vivo Y73s 项目当前状态（唯一状态入口）

> 更新时间：2026-11-09（已完成资料库原始 Boot 离线复核）  
> 当前分支：`y73s-cred-layout-guards-20261108`  
> 本文是当前状态的权威摘要。历史审计报告保留技术证据；若历史记录与本文状态冲突，以本文和对应最新源码/CI 记录为准。

## 1. 当前结论

当前分支的主机工具构建、Y73s ARM64 KPIMG 构建、通用工作流中的 KPIMG 构建，以及 LKM/KPM 源码契约审计均已通过 GitHub Actions。

**这不等于 LKM 已针对 vivo Y73s 的 Linux 4.14.141 内核成功编译，也不等于 KPIMG 或 LKM 已在手机上启动成功。** 当前没有目标 KDIR 编译、真机运行、APatch 初始化或 root 验证结果，因此项目仍是实验性源码，不可标记为设备可用或可安全刷入。

## 2. 当前分支与最近提交

- 分支：[`y73s-cred-layout-guards-20261108`](https://github.com/ljx-91/kptools-fix/tree/y73s-cred-layout-guards-20261108)
- 最近已通过上述三类 CI 的源码提交：[`ed8de7e35e5594a348c7c1d98d7fc4740994728a`](https://github.com/ljx-91/kptools-fix/commit/ed8de7e35e5594a348c7c1d98d7fc4740994728a)。其后的提交仅整理文档，没有改动构建源码。
- 目标：Vivo Y73s / MTK / Android 10 / Linux 4.14.141（具体内核构建配置仍须由目标 KDIR 和设备镜像确认）。

## 3. 最新 CI 结果

| 工作流 | Run | 结果 | 证明范围 |
|---|---:|---|---|
| 通用 KernelPatch Windows Build | [42635152067](https://github.com/ljx-91/kptools-fix/actions/runs/42635152067) | 通过 | Y73s KPIMG 编译、kptools.exe 构建 |
| Y73s GCC 14.2 KPIMG | [42635153069](https://github.com/ljx-91/kptools-fix/actions/runs/42635153069) | 通过 | Y73s 专用 ARM64 KPIMG 构建与打包 |
| Y73s host kptools + LKM audit | [42635152168](https://github.com/ljx-91/kptools-fix/actions/runs/42635152168) | 通过 | 主机端 kptools 构建/打包及 LKM KPM 源码契约审计 |
| 最新 HEAD 通用构建 | [42637030872](https://github.com/ljx-91/kptools-fix/actions/runs/42637030872) | 通过 | 最新文档 HEAD 对应的 KPIMG 与 Windows kptools 构建 |
| 最新文档同步构建 | [42636951611](https://github.com/ljx-91/kptools-fix/actions/runs/42636951611) | 通过 | KPIMG 与 Windows kptools 构建 |

这些结果不覆盖目标内核 KDIR 编译、KPM 动态加载、设备启动或运行时并发压力测试。

## 4. 已落地的关键修复

### KPIMG / Y73s 启动映射路径

- 修正 Y73s 定向物理内存分配路径，拒绝把返回虚拟地址的 `memblock_alloc_try_nid` 当作物理地址使用。
- 对 memblock 相关必需符号采用 fail-closed 检查。
- 增加主映射 PA、页对齐、范围溢出及中间页表分配检查。
- 对 early-boot hook、ARM64 指令重定位、entry thunk 解析和 hook 失败回滚路径增加边界保护与回归检查。
- 当前构建工作流已确保所选分支启用 `Y73S_TARGET=1`，避免使用错误的通用映射布局。

### LKM / KPM 加载器与生命周期

- 加强 ELF header、section、字符串表、符号表和 RELA 元数据验证。
- 增加安全布局、拷贝范围、重定位目标边界和失败回滚检查；不支持的 REL 类型明确拒绝。
- 修复 RELA 符号表 `sh_entsize` 在布局阶段被复用后导致合法重定位被错误拒绝的问题。
- 加强模块注册、卸载状态、活动调用计数和 callback owner 引用检查。
- KPM 可执行代码及 callback trampoline 发布统一调用内核 `flush_icache_all()`；该符号不可用时拒绝初始化，避免仅做本地 CPU 指令缓存失效。
- CI 独立执行 `scripts/verify_lkm_kpm_contract.py`，不把 KPIMG 检查误当成 LKM 检查。

## 5. 资料库原始 Boot 离线审计（2026-11-09）

新增 [Y73S_BOOT_OFFLINE_AUDIT_20261109.md](Y73S_BOOT_OFFLINE_AUDIT_20261109.md)，直接绑定本轮资料库镜像 SHA-256，记录原始 Boot 布局、内核配置、AVB descriptor 和已有 KPIMG 候选镜像的复核结果。

本轮从原始 Boot 内嵌 IKCONFIG 确认了此前尚未明确记录的关键目标配置：

- Linux 4.14.141+，ARM64，4KB pages，VA_BITS=39。
- `CONFIG_MODULES=y`、`CONFIG_MODULE_UNLOAD=y`、`CONFIG_MODVERSIONS=y`。
- `CONFIG_LTO_CLANG=y`、`CONFIG_CFI_CLANG=y`、`CONFIG_CFI_CLANG_SHADOW=y`。
- `CONFIG_KPROBES` 未启用，`CONFIG_KALLSYMS_ALL` 未启用。
- 原始 Boot HashDescriptor 摘要与资料库原始 `boot.img` 实算值匹配。
- 现有 KPIMG 候选保留原始嵌入 VBMeta，但其 Boot HashDescriptor 摘要不匹配；候选不是 AVB 验证通过的镜像。

**对后续代码工作的直接影响：** 不能只追求普通 host build。下一阶段必须围绕精确的 4.14.141 KDIR、`Module.symvers`、生成头文件、Clang 9.0.3、MODVERSIONS、LTO 和 CFI shadow 进行兼容性审计。当前源码契约 CI 不证明目标 .ko/KPM 已通过这些约束。

## 6. 尚未关闭的验证门槛

1. 获取并确认与目标手机固件完全匹配的 Linux 4.14.141 内核源码、生成头文件、配置、DDK/Kbuild 和工具链。
2. 对 `lkm/kernelpatch.ko` 执行真实目标 KDIR 编译，解决所有编译、链接和 modpost 问题。
3. 对 KPM ELF 加载器执行畸形 ELF/RELA 输入测试，以及失败回滚测试。
4. 在可恢复的隔离内核环境中进行 Hook 安装/卸载、KPM load/unload、并发调用和 callback 生命周期压力测试；可用时启用 lockdep/KASAN。
5. 逐项验证目标内核符号 ABI、CFI/PAC/BTI、早期启动时序和内存映射语义。
6. 只有在上述证据完整后，才制定独立的真机验证方案。

## 7. 安全边界

- 不使用 Fastboot。
- 不执行刷机、boot/vbmeta 修改或任何分区写入。
- 不把 KPIMG 构建成功、静态 patch 成功或源码审计通过解释为设备可启动。
- 不把通用 DDK 示例目标（例如 Android 12 / Linux 5.10）当成 Y73s Linux 4.14.141 的兼容性证明。

## 8. 本轮文档清理

- 新增本文作为唯一当前状态入口。
- 将根 README 和 Y73s README 改为指向本文，避免多个文件分别维护状态。
- 将 allocator、runtime failure、hook concurrency 报告明确标记为历史技术证据，防止把旧章节中的阶段性“未修复”误认为当前状态。
- 将 map/stack follow-up 中仍有价值的 memblock ABI 和 ELF 栈帧验证限制并入 runtime failure 审计后，删除重复文件。
- 删除过时的独立 GCC audit 分支摘要；其有效技术结论保留在 allocator/runtime/hook 深度审计中。
- 旧版本机编译和 boot 只读数据保留在 `BUILD_VALIDATION_CN.md`，但已标注为历史记录，不再作为当前 CI 状态。

## 9. 文档索引

- [原始 Boot 离线审计](Y73S_BOOT_OFFLINE_AUDIT_20261109.md)：Boot/DTB 布局、内嵌内核配置、AVB descriptor 与候选镜像复核。
- [Y73s 定向工具改动说明](OPTIMIZATION_Y73S_CN.md)：kptools 严格 Kallsyms、镜像布局、密钥日志处理和历史构建方法。
- [Allocator ABI 深度审计](Y73S_ALLOCATOR_DISPATCH_AUDIT.md)：原始内核符号、反汇编证据、memblock ABI 与映射路径修复历史。
- [Runtime failure 深度审计](Y73S_RUNTIME_FAILURE_AUDIT.md)：KPIMG 早期启动、映射、stack-frame、hook 与 relocation 的历史缺陷和验证记录。
- [Hook concurrency / LKM KPM 深度审计](Y73S_HOOK_CONCURRENCY_AUDIT.md)：Hook 生命周期、模块管理、ELF/RELA 边界、LKM 修复和 CI 记录。
- [LKM 实现与验证边界](lkm/README.md)：LKM 架构、当前 CI 覆盖范围及目标 KDIR 验证要求。
- [历史只读构建记录](BUILD_VALIDATION_CN.md)：旧版本本机编译和用户提供 boot 的只读解析数据；不是当前 CI 状态。

旧的分支阶段摘要和重复的 map/stack follow-up 记录不再作为当前状态入口；其仍有价值的技术结论已并入上述深度审计或本文。
