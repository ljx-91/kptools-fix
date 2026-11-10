# Vivo Y73s 项目当前状态（唯一状态入口）

> 更新时间：2026-11-10  
> 当前分支：`y73s-cred-layout-guards-20261108`  
> 最近代码修复基线（不含本次状态文档提交）：`980bec8310860927aaf3469a607e1484e79579c0`  
> 本文是当前状态的权威摘要；历史审计报告保留技术证据，若历史记录与本文冲突，以最新源码和 CI 为准。

## 1. 当前结论

本轮完成了 KPIMG 启动映射、LKM/KPM ELF 与 ARM64 重定位、凭据偏移保护、任务扩展身份校验及 Kbuild 条件参数优化。

- 2026-11-09 代码基线的 Y73S GCC 14.2 KPIMG、Host kptools 和 Windows 构建曾通过。
- 2026-11-10 的 Kallsyms/RELA/名称解析、Boot repack 和 map-hole/PAC 边界修改已由当前 HEAD 的 Linux Host、GCC 14.2 KPIMG、Windows 三条 Actions 全部验证成功（Run 见第 17 节）。
- 目标 Linux 4.14.141 的真实 `.ko` 编译、KPM 动态加载、设备启动和 APatch/root 验证：尚未完成。

**因此当前结论是源码与 KPIMG 构建阶段取得进展，不是设备可用或可刷入版本。**

## 2. 分支与最近 CI（历史基线）

- 分支：[y73s-cred-layout-guards-20261108](https://github.com/ljx-91/kptools-fix/tree/y73s-cred-layout-guards-20261108)
- 本次文档更新前最近代码与契约提交：[26dc2e1](https://github.com/ljx-91/kptools-fix/commit/26dc2e1bf4acfb9f605c18751f59a6787f6c71a8)

| 工作流 | Run | 结果 | 证明范围 |
|---|---:|---|---|
| Y73S Android KPIMG / GCC 14.2 | [42678135541](https://github.com/ljx-91/kptools-fix/actions/runs/42678135541) | 成功 | 当前 HEAD KPIMG 构建、栈帧与映射审计、打包 |
| Y73S host kptools + source contracts | [42678135670](https://github.com/ljx-91/kptools-fix/actions/runs/42678135670) | 成功 | Host 工具构建、全量源码契约验证 |
| KernelPatch Windows Build | [42678135438](https://github.com/ljx-91/kptools-fix/actions/runs/42678135438) | 成功 | Windows kptools.exe 构建及打包 |

上述 Run 是 2026-11-09 旧代码基线的历史结果，不代表 2026-11-10 最新 HEAD。全量源码契约审计包含 bootimg I/O、kptools patch bounds、KPIMG loader、KPM lifecycle、LKM/KPM contract、ELF/RELA loader、Hook runtime、supercall input、userd file、Y73s fphook、memblock 和 runtime contract 检查。

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


## 7. 2026-11-10：Kallsyms 相对偏移扫描边界修复

针对 KernelPatch 上游 Y73S / Linux 4.14.141 问题记录（#189）及其严格 Kallsyms 修正讨论（PR #208），重新核对本分支工具代码：

- 本分支已经使用 `KP_STRICT_KALLSYMS`：无法确认精确 `kallsyms_num_syms` 时拒绝候选并重试，不退回猜测符号数量；不直接照搬旧 PR 的实现。
- 发现 `tools/kallsym.c::find_approx_offsets()` 在定位相对偏移表前，存在两个无边界的向前回扫循环；畸形或异常输入可能使 `cand` 变成负值后仍执行 `img + cand` 读取。
- 已将回扫限制在 `cand >= 0`，在每次读取前校验候选起点，并将表尾扫描限制为完整的 `elem_size` 项，避免尾部不足一个元素时越界读取。
- `scripts/verify_kptools_patch_bounds.py` 新增对应源码契约，防止无界回扫和不完整元素读取回归。
- 代码提交：`e066808ec7634e68963c1cd083d1f0930a4cc0d2`；边界契约提交：`913ad26cc4a42775f471c6d2759940c19695da8e`；扫描实现提交：`336754854094c5c1c7125f96498887ca53f41a26`。
- **验证状态：** 已推送到本分支；对应 GitHub Actions 新一轮结果尚未取得。不能把源码修复或契约加入等同于 CI 通过，更不能等同于 Y73s 真机验证。

外部参考：
- KernelPatch Y73S 4.14.141 issue #189：`https://github.com/bmax121/KernelPatch/issues/189`
- Strict Kallsyms PR #208：`https://github.com/bmax121/KernelPatch/pull/208`


## 8. 2026-11-10：Kallsyms 输入边界与 ARM64 RELA 扫描加固

本轮继续审计 `tools/kallsym.c`，重点处理畸形/截断内核镜像输入下的越界读取、越界写入和错误基址状态：

### Token Table / Token Index

- 数字 Token 搜索后，检查剩余镜像长度再读取后续字节。
- 字母 Token 序列使用有界比较；不足完整 20 字节时拒绝候选。
- 回扫 Token Table 前缀时要求找到完整的历史终止符数量，否则拒绝。
- 重建 256 个 Token 时，逐项使用镜像范围内的 NUL 搜索；缺失终止符即失败。
- 生成 Token Index 时再次验证每个 Token 的边界，并拒绝超出 16 位索引范围的偏移。

### 名称解压和符号索引

- `kallsym_t` 增加已验证的 `image_size`，在分析入口保存镜像长度。
- `decompress_symbol_name()` 检查名称游标、markers 终点、压缩长度、Token 指针、Token 终止符和解压后输出容量。
- 符号遍历/查询调用者在解压失败时停止，不再继续使用空或部分解码结果。
- `get_symbol_index_offset()` 检查索引范围和完整地址项覆盖；绝对地址转换拒绝低于基址或超过有符号 32 位偏移范围的结果。
- 分析镜像的临时副本分配失败时立即返回，不再对空指针执行 `memcpy`。

### ARM64 RELA 与地址表扫描

- RELA 候选不足最小项数时，在回扫前直接退出。
- 候选起止范围经过验证；尾部全零项回扫不能越过候选起点。
- 将尾部空项判断改为“三个字段全零”；合法的零 addend 项不再被误删。
- 只有候选 RELA 表通过长度/范围检查后才提交 `kernel_base`；无表或无有效基址时不再把 `UINT64_MAX` 留作伪基址。
- relocation 目标先以 64 位差值验证，再缩窄成 32 位镜像偏移。
- 绝对地址表尾部扫描只读取完整的 4/8 字节元素；相对偏移表按 Linux KALLSYMS ABI 限定为 32 位项。Linux Kconfig 文档说明 base-relative 表使用 32-bit entries，4.14 的 `kernel/kallsyms.c` 也按 `int` 读取 offsets。

### 提交与验证

- 本轮源码修复及回归契约已推送到本分支，相关提交包括：
  - `7655f8d`、`66609de`、`c8023ec`：Token Table/Index 与符号计数扫描边界。
  - `c27903d`、`5d58f49`、`cb0330f`、`d4464a6`：ARM64 RELA 候选范围、零 addend 和基址状态。
  - `3321fc5`、`60c87e6`、`4353735`：绝对/相对地址表扫描边界。
  - `e17fddf`、`42d2517`、`17c8a8d`、`e0d3e03`、`89833ca`：解压边界、image_size、符号索引及失败传播。
  - `969d0a9`、`d0b8f10`、`8769b19`、`1e77033`、`10f74af`、`bb29161`、`fb8cdee`、`8d3422d`：源码契约和正则断言修正。
- `build-y73s-kptools-host.yml` 已在 `tools/**` 和 `scripts/**` 变更时触发，因此这些提交会进入 Host 契约工作流。
- **CI 状态：** 当前 GitHub 状态查询未返回可确认的 checks/run 记录；本轮契约尚不能标记为 CI 通过。必须等到实际 Actions 运行结果或本地执行记录。
- **目标 KDIR、Linux 4.14.141 .ko 编译、KPM fuzz/load/unload 和真机验证仍未完成。**

外部 ABI 依据：
- Linux `CONFIG_KALLSYMS_BASE_RELATIVE` 说明：<https://cateee.net/lkddb/web-lkddb/KALLSYMS_BASE_RELATIVE.html>
- Linux v4.14 Kallsyms 实现：<https://kernel.googlesource.com/pub/scm/linux/kernel/git/stable/linux-stable.git/+/refs/tags/v4.14.264/kernel/kallsyms.c>


## 9. 2026-11-10：Kallsyms 解析链完整边界审计

在第 8 节基础上继续检查 Linux Kallsyms 解析入口和 ARM64 的 fallback：

### Linux banner / IKCONFIG / marker / names

- `find_linux_banner()` 不再在没有匹配 banner 时访问 `linux_banner_offset[-1]`；每次前缀探测都验证剩余长度，最多保留结构体可容纳的 4 个 banner 偏移。
- 版本字符串先在镜像边界内定位空格，再复制到固定长度缓冲区解析 major/minor/patch；拒绝截断和格式错误输入。
- `find_ikconfig_blob()` 验证输入长度和输出指针，所有 marker 搜索都限制在镜像范围。
- `find_markers_internal()` 验证初始读取位置和 marker table 终点。
- 恢复并加固 `verify_names_candidate()` / `find_names()`：压缩名称长度使用减法边界判断，marker index 和 marker table 读取均验证完整范围，候选窗口运算使用 64 位中间值。

### 名称解压 / 地址表候选

- 解压器基于 `kallsym_t.image_size` 和 markers 终点检查所有输入。
- Token 指针、NUL 终止、解压字符串容量和符号索引均有边界保护。
- 查询、遍历和导出符号的调用方会传播解压/索引失败。
- ARM64 vector fallback 限定为 ARM64，搜索窗口和索引偏移使用 64 位运算；地址差值在缩窄前检查，保留高半区 canonical kernel VA 的无符号语义。
- ARM64 相对偏移扫描使用 32 位无符号表项解释，避免把高位设置的合法 offset 错当作负数并反转排序。
- ARM64 指令窗口与 CFI 分支目标均使用 64 位偏移并验证完整 4 字节指令。
- Kallsyms 分析失败时不再把部分重定位后的临时镜像复制回调用者缓冲区。

### 当前提交与验证状态

- 本轮后续源码提交包括：`7b1e98c`、`e2bff68`、`bf736f7`、`fa0d422`、`7d40828`、`d7c6cb9`、`03fb4a2`、`a9a5e8d`、`9e49f0c`、`0e2aaf5`、`6b6d282`、`bfcf5c9`、`d47c8b6`、`36520d2`、`10b8d5b`、`dcbf9d1`、`d7c8095`、`cc5c9ba`、`3f69f88` 等。
- `scripts/verify_kptools_patch_bounds.py` 已增加 banner、IKCONFIG、marker、names、decompressor、ARM64 vector、RELA 和失败回滚契约。
- `build-y73s-kptools-host.yml` 的 push 触发范围覆盖 `tools/**` 和 `scripts/**`，且执行 Host 构建与该契约脚本。
- 最新 HEAD 的 GitHub combined status 没有返回 checks；工作流运行查询也没有返回可确认的 run。**当前状态只能标记为已推送、待 CI，不可标记为通过。**
- 后续又补强了无 `linux_banner` 场景：`find_linux_banner()` 在没有可用 banner 时安全返回并保留 vector fallback，不会让 `base_funcs` 提前中止；每次解析前清零旧版本元数据。相关提交：`a510b12`、`913892f`、`5ce8251`、`5ace991`；回归契约：`75762ed`、`04a712b`。
- 已对当前源码执行 8 项关键结构断言（无 banner fallback、版本元数据复位、names/vector 函数存在、names 边界、ARM64 无符号地址语义、RELA 回扫和失败回滚），8/8 符合预期。这是源码结构检查，不是 C 编译或 Actions 成功证明。
- 目标 Linux 4.14.141 KDIR 编译、真实 `.ko` modpost、KPM fuzz/load/unload 和真机启动仍未完成。



## 10. 2026-11-10：使用资料库原始 Y73s Boot 做离线行为核对

本轮从资料库重新取得原始 `boot.img`，只在工作目录副本中解包和分析，没有修改资料库原件，也没有连接设备。

### 输入一致性

- 文件大小：100,663,296 bytes。
- SHA-256：`c47e94f64696fe70de11ea26cda4a3e0e6e025e581e7a96b95f1d975c9fe7cd5`，与 2026-11-08 原始 Boot 离线报告一致。
- Android Boot Header v2，page size 2048。
- gzip 内核解压为 47,517,708 bytes，和既有记录一致。

### 真实 Kallsyms / ARM64 fallback 基线

使用资料库中已有的旧版 kptools（KPIMG 版本标识 d09）对解包副本执行只读 `-d` 分析，得到：

- Linux 4.14.141+ / ARM64，kernel base 最终为 `0xffffff8008080000`。
- `kallsyms_addresses` 最终定位到 `0x01c1c700`，`kallsyms_num_syms=0x1a5b9`。
- names table 中没有 `linux_banner` 符号（`CONFIG_KALLSYMS_ALL=n`），但存在 `vectors`（index `0x12`）和 `pid_vnr`（index `0xd165`）。
- `vectors` 地址相对 kernel base 为 `0x2800`；后一个符号相对地址差为 `0x7d8`。
- `pid_vnr` 相对地址为 `0x01912460`。入口是 B veneer 指令 `0x17a025ec`，跳转到 `0x0011bc10`，目标指令 `0xd5384108`，对应 SP_EL0 读取路径。
- 独立离线解析 RELA 表范围 `[0x02554218, 0x02af9c60)`，按目标 base 计算并应用 246,723 项后，确认前三个地址项确实相同（`0xffffff8008081000`），与 strict ARM64 vector alias guard 的假设一致。

### 对当前分支修复的意义

- 明确验证 Y73s 必须保留“names table 找不到 `linux_banner` 时转入 ARM64 vector fallback”的路径。因此 `find_linux_banner()` 在无 banner 时安全返回 0，而不是让 `base_funcs` 提前中止；`correct_addresses_or_offsets()` 再尝试 vector fallback。
- 当前分支 vector fallback 的 64 位无符号地址差、前三项 alias 检查、pid_vnr CFI/B veneer 跳转和 SP_EL0 指令验证，均与这份真实镜像的已知值吻合。
- 这是一项基于真实镜像数据的离线行为核对；使用的旧 kptools 二进制不是本轮最新源码构建，独立 Python RELA/vector 计算也不是新 C 程序执行。因此不能把它描述成“最新源码已通过真实镜像端到端测试”。
- 最新源码仍需 Host CI 实际构建确认；目标 Linux 4.14.141 KDIR、.ko 编译、KPM 动态测试和真机验证仍未完成。
- 全程没有 Fastboot、刷写、分区写入或设备启动操作。

资料库依据：原始 Boot 离线记录、原始 Boot 注入记录和既有 Kallsyms 日志。


## 11. 2026-11-10：修复真实 Boot Token Table 起点偏移

### 复现与根因

使用 CI 构建的 kptools（HEAD `67ab6611`）解包资料库原始 Boot 后执行只读 `-d`：

- Boot SHA-256 与第 10 节一致；解压内核大小为 47,517,708 bytes。
- 新工具识别 Linux 4.14.141 和 banner，但在 `find_token_index()` 报错。
- 进一步定位发现 `find_token_table()` 的反向扫描改成 `while` 后，循环退出时 `pos` 仍指向第 49 个 NUL；旧 `for` 循环退出时则已额外递减一次。
- 旧的 `pos + 2` 算式没有随循环语义变化，导致 token table 起点从真实的 `0x01e4bd00` 错算成 `0x01e4bd04`。

### 修复和独立镜像核对

- `tools/kallsym.c` 改为 `pos + 1 - img`，并明确注释 pos 仍指向最后扫描到的 NUL。
- `scripts/verify_kptools_patch_bounds.py` 新增回归断言，防止循环语义与偏移公式再次不一致。
- 使用原始解压内核独立复算 256 个 token：token table 起点 `0x01e4bd00`，末端 `0x01e4c05a`；生成的 little-endian 512-byte token index 唯一命中 `0x01e4c100`。这与历史成功日志中的 token table/index 地址一致。
- 源码修复提交：`0d66377b59062c29b50b9dfd0a2e14be85c774bf`；回归脚本提交：`b157e578888793e9155ccbba98bbcde5e2fdd59b`。

### CI 状态

- `b157e578` 触发 Linux kptools、GCC 14.2 KPIMG 和 Windows 工作流；截至本次记录，工作流处于 queued，尚无最终结果。
- **尚未用包含此修复的最新 C 二进制完成真实 Boot 端到端解析。** 独立 Python token-table/index 计算确认了偏移根因与预期地址，但不能代替 C 工具测试。
- 继续等待最新 CI，成功后下载该 run 的 kptools artifact，在解压内核副本上执行 `-d`，确认输出与历史日志一致。
- 不使用 Fastboot，不刷写、不写设备分区，不进行真机启动测试。


### 11 节验证状态补充（HEAD `e0b3c5df7f8a233a562b2586d3b6d9f68fe42d18`）

- 最新 `KernelPatch Windows Build` Run `42672374856`：**success**。其中 Ubuntu ARM GNU GCC 14.2 KPIMG 构建、头文件生成与打包均通过；Windows kptools.exe 编译和 artifact 上传也通过。
- 独立 `Build Linux kptools for Y73S offline audit` Run `42672375072`：GitHub 返回 failure，但该 run 的 jobs/check-runs 查询均为空，未提供可诊断的 step/log；因此不能确认是源码、契约脚本还是 Actions 调度问题，也不能算作 Linux Host 构建通过。
- 独立 KPIMG Run `42672375021` 同样返回 failure 且无可读取 job 记录；但同一 commit 的 Windows workflow 中 Ubuntu KPIMG job 已实际成功完成。
- 现有成功 artifact 是 KPIMG/headers 与 Windows kptools；尚未生成包含 Token Table 起点修复的 Linux kptools artifact，故真实 Boot C 工具端到端复测仍待完成。


## 12. 2026-11-10：Token Table 修复后的独立 C 验证与 CI 追踪

### 已完成的额外验证

- 对原始 Boot 解压得到的 47,517,708-byte ARM64 Image 重新执行 49 个 NUL terminator 的反向游标模型。
- 用独立 C harness 复现仓库当前 `find_token_table()` / `find_token_index()` 的边界与偏移算法，并直接读取原始解压内核：
  - Token Table：`0x01e4bd00`
  - 256 个 token 的终点：`0x01e4c05a`
  - Token Index：`0x01e4c100`
  - Endian：little
  - 512-byte index 表唯一匹配。
- 合成回归模型确认 `while` 游标 `pos + 1` 与旧 `for` 游标 `pos + 2` 得到相同起点；四字节对齐后结果一致。
- 发现并修正了回归模型本身的两处问题：期望偏移应为 5（不是 4）；NUL fixture 使用 `bytes(49)`，确保是真正的 NUL 字节。最新脚本提交：`0f6f68f`。

### CI 追踪（不把空工作流误报成通过）

- 修复前的 CI artifact（`67ab6611`）确实在 Token Table 偏移多 4 字节后于 `find_token_index()` 失败；该 artifact 不是修复后构建。
- `38e39fce` 的 host 构建实际编译通过，但两处源码契约 job 都被合成 fixture 错误挡住；失败日志已定位为测试 fixture，而非 C 编译器错误。
- 修正 fixture 后，`0f6f68f` 对应的专用 Host / Windows 工作流显示 workflow-level failure 且没有创建任何 check runs/jobs；这不是可归因于源码的失败，也不能算通过。专用 GCC KPIMG workflow 仍处于 pending。
- 因此当前**真实镜像的 Token Table / Token Index 算法已由独立 C harness 和 Python 双重验证，但修复后的完整 kptools CI artifact 尚未生成，完整 C 工具端到端 `-d` 仍待执行**。
- 下一步：等待专用 Host workflow 正常创建 jobs；拿到修复后 artifact 后，对同一份解压内核运行 `-d`，核对完整 Kallsyms、vector fallback 和符号导出结果。

安全边界继续有效：不使用 Fastboot，不刷写、不写设备分区，不做真机启动测试。


## 13. 2026-11-10：修复后跨平台构建状态

- `tools/kallsym.c` 的 `pos + 1` 修复已包含在后续 Windows kptools 构建源码中。
- GitHub Actions 通用构建 Run `42673376096`（源码提交 `c7caef3a`）最终成功：
  - GCC 14.2 ARM64 KPIMG 构建、ELF stack-frame / map-relocation 审计成功。
  - Windows `kptools.exe` 编译、打包成功。
- 专用 Linux Host Run `42672967489` 已实际执行编译；`make` / C 编译阶段通过，但构建步骤被当时错误的 synthetic NUL fixture 拦截，未生成 artifact。fixture 随后已改为 `bytes(49)`，并补上对齐结果断言（提交 `4c34c8b`）。
- 专用 Linux Host Run `42673414886` 对 `4c34c8b` 显示 workflow-level failure，GitHub 未创建 jobs/check-runs；没有源码失败日志，不能判定为 C 编译失败或通过。
- 因此：修复后的 C 源码已通过 Windows 编译；Linux Host C 编译曾通过，但修复后的回归脚本尚未在有效 Host CI job 中跑完；**修复后完整 Linux kptools artifact 和完整 C 工具真实 Boot `-d` 结果仍待确认**。


## 14. 2026-11-10：原始 Y73s Boot 的完整 Kallsyms 离线解析通过

### 第二处根因与修复

- 最新 C 工具在 Token Table/Index 修复后，名称解码仍失败。
- 根因：`kallsyms_token_table[]` 保存的是原始输入镜像内的指针；分析流程为 RELA 使用 `copied_img` 工作副本，但 `decompress_symbol_name()` / `is_symbol_name_pos()` 错误地用工作副本基址验证原始镜像指针，造成合法 token 指针被拒绝。
- `kallsym_t` 新增 `kallsyms_token_table_image` 保存 token 指针所属的原始镜像；新增 `get_token_string()` 统一执行 token 地址、镜像范围和 NUL 终止检查。名称解码和符号探测均改为使用该 helper。
- 在独立 ASan/UBSan C harness 中，以原始镜像保存 token 指针、以复制镜像解码名称，成功找到 `vectors` index 18 和 `pid_vnr` index 0xd165；Token Table 截断边界用例也全部安全返回。

### CI 与真实镜像验证

- Linux Host kptools + 全量源码契约 Run `42674779169`（HEAD `d9e4e0dc`）：success。
- 构建产物：`kptools-linux-x86_64`，SHA-256 `a9fef9972e451305a1efc3e5a7ce888258c10241750967f61c5b41648191d06f`。
- 使用上述产物，对资料库原始 Boot 解压出的 47,517,708-byte ARM64 Image 执行只读 `-d`：**exit code 0**。
- 最终解析结果：
  - Linux 4.14.141+，ARM64。
  - token table `0x01e4bd00`；token index `0x01e4c100`；markers `[0x01e4af00, 0x01e4bc30)`；names `0x01cef600`。
  - `kallsyms_num_syms=0x1a5b9`，完整导出 107,961 条符号。
  - `vectors` index 18，offset `0x2800`。
  - `pid_vnr` index `0xd165`，offset `0x01912460`；CFI B veneer 跳到 `0x0011bc10`，目标指令 `0xd5384108`，成功识别 SP_EL0。
  - kallsyms addresses `0x01c1c700`；kernel base `0xffffff8008080000`。
- 之后统一构建 Run `42674985016`（提交 `e2dfebec`）最终全部 success：Ubuntu GCC 14.2 KPIMG、Linux kptools 编译与全量源码契约、Windows kptools.exe 编译和 artifact 上传均通过。
- 该结果证明原始 Boot 的完整 Kallsyms 离线解析链已通过；不代表目标设备已启动、APatch 已初始化或真实 `.ko` 已在设备加载。

安全边界不变：没有使用 Fastboot、没有刷写或写设备分区、没有进行真机启动测试。


### 最新 HEAD 复测结果（提交 `e2dfebeca4fa714b4a0ee99c84670bff18f20211`）

- 从 Run `42674985016` 下载当前 HEAD 的 `kpimg-and-headers` artifact，内含 Linux `kptools`；工具 SHA-256：`a9fef9972e451305a1efc3e5a7ce888258c10241750967f61c5b41648191d06f`。
- 原始 Boot SHA-256：`c47e94f64696fe70de11ea26cda4a3e0e6e025e581e7a96b95f1d975c9fe7cd5`；解压内核 Image 大小 47,517,708 bytes，SHA-256：`345bfab8217669cb84ed004916efea4fae06e6b169c70e1be2ec9ac3ad4f093e`。
- 在该解压内核副本上执行 `kptools -d -i kernel`，实际退出码 **0**；完整导出 107,961 条符号，等于 `0x1a5b9`。
- 新旧两份完整符号列表逐行完全一致；符号行规范化 SHA-256：`b551f2cd3fae3b58677796b95db6044adf4725f9814f35df2342f23479d7654f`。
- 最新输出再次确认 Token Table `0x01e4bd00`、Token Index `0x01e4c100`、Markers `[0x01e4af00, 0x01e4bc30)`、Names `0x01cef600`、Addresses `0x01c1c700`、kernel base `0xffffff8008080000`；`vectors` index 18 / offset `0x2800`，`pid_vnr` offset `0x01912460`，CFI veneer 跳转和 SP_EL0 指令校验通过。
- 日志中的 `find approximate kallsyms_offsets error` 是此固件不采用相对 offsets 表时的预期回退；前两次候选的 symbol-count 不匹配被严格拒绝，第三次候选以精确 count 和 vectors/pid_vnr 双重验证通过。上述警告不是被忽略的致命错误。
- 测试只解包并读取工作目录副本，未修改资料库原始 Boot；没有 Fastboot、刷写、分区写入或设备启动操作。

当前阶段结论：**源码契约、Host Linux 工具构建、KPIMG 构建、Windows 工具构建和原始 Y73s Boot 的完整 Kallsyms 离线解析均已通过。** 尚未通过目标 Linux 4.14.141 KDIR 的真实 `.ko` 编译/modpost、KPM 动态 load/unload 与 Hook 压力测试，也未进行真机启动/APatch 初始化；不能据此宣称设备可启动或 APatch 已可用。


## 16. 2026-11-10：Boot repack 成功路径、AVB 边界与原始配置提取

### Boot repack 修复

- `repack_bootimg_mem()` 在成功写出并关闭输出文件、释放缓冲区后，原先会顺序落入 `write_fail:`，再次清理并错误返回 `-EIO`。现在成功路径显式 `goto post_write`，跳过失败清理。
- AVB footer 校验失败的早退分支此前遗漏释放 `compressed_buf`、`extracted_dtb`、`rest_buf` 和独立的 `rest_buf_tmp`；现已补齐释放。
- 对带 AVB footer 的 repack 增加明确警告：工具只保留 AVB metadata/footer 字节并调整 footer offset，不重新计算分区 digest 或 AVB signature；输出不得被当作 AVB-verified 镜像。回归契约已锁定成功跳转、失败清理和该警告。
- 主要提交：`8a74d4cf`（成功路径控制流）、`d023bad2`（AVB 错误路径清理）、`dfc651a4` / `e60fc9a6`（AVB 验证警告及契约）。

### 原始 Boot 的只读 round-trip

使用当前分支构建的 Linux kptools（Host Run `42676275704`，工具 SHA-256 `774e856fdddf9ae8154573f16186695ed76a6cefe7b72b49a460686b2d988994`）：

- 在独立临时目录对原始 Boot 副本执行 `kptools repack boot.img`，退出码 0，输出 `new-boot.img` 为 100,663,296 bytes。
- 再对输出执行 `kptools unpack`，退出码 0；解压内核 SHA-256 与原始解压内核完全相同：`345bfab8217669cb84ed004916efea4fae06e6b169c70e1be2ec9ac3ad4f093e`。
- AVB footer magic 保留；原 vbmeta 1,472 bytes 在新 offset 上逐字节相同。footer 的 image_size 从 17,618,944 调整为 17,602,560，vbmeta_offset 从 17,620,992 调整为 17,604,608，偏移变化 -16,384 bytes。
- **限制：这只是 Boot 结构、解压内核和 metadata 搬移的 round-trip 检查；没有重算或验证 AVB 分区摘要/签名。工具现已在日志中明确警告，不得将该输出当作 AVB 验证通过。** 未将输出写入设备。

### 从原始内核提取真实 .config

- 原始解压内核包含 `IKCFG_ST` / `IKCFG_ED`，成功解出 gzip 内嵌配置。
- 配置标头为 Linux/arm64 4.14.141；文件 148,327 bytes，SHA-256：`8edad6360e3769bf32e505d54be40bfafc31695d2e4762dac8fc246607d3c934`。
- 已确认关键项：`CONFIG_MODULES=y`、`CONFIG_MODVERSIONS=y`、`CONFIG_MODULE_UNLOAD=y`、`CONFIG_LTO_CLANG=y`、`CONFIG_CFI_CLANG=y`、`CONFIG_CFI_CLANG_SHADOW=y`、`CONFIG_MACH_MT6853=y`、`CONFIG_KALLSYMS_ALL=n`、`CONFIG_PGTABLE_LEVELS=3`、`CONFIG_ARM64_4K_PAGES=y`、`CONFIG_ARM64_VA_BITS=39`；`CONFIG_MODULE_SIG` 未启用。
- 这份精确配置有助于未来恢复 KDIR，但不能替代源码、生成头文件和 `Module.symvers`。

### 公开源码候选核验

- 发现 `vivo-source-mirror/Y53s` 有 PD2031 专用 defconfig 和 `k6853v1_64_6360_PD2031.dts`，可作为 MT6853/PD2031 平台参考。
- 但该仓库顶层 Makefile 是 Linux 4.14.186，不是本机 Boot 的 4.14.141；仓库也没有生成后的 `include/generated` 和 `Module.symvers`。因此它**不是当前 Boot 可直接使用的 KDIR**，没有拿它编译或声称生成可加载模块。
- 公开源码候选：`https://github.com/vivo-source-mirror/Y53s`；Makefile：`https://github.com/vivo-source-mirror/Y53s/blob/master/Makefile`；PD2031 defconfig：`https://github.com/vivo-source-mirror/Y53s/blob/master/arch/arm64/configs/k6853v1_64_6360_defconfig_PD2031`。

### 当前代码 CI

- Linux Host kptools + 全量源码契约：Run `42676275704` success。
- GCC 14.2 ARM64 KPIMG：Run `42676275468` success。
- Windows kptools.exe：Run `42676275493` success。
- 当前验证提交：`e42ee0031f1c10b2ecf68d67c5029d3db095df76`。

剩余门槛仍是匹配 4.14.141 的源码/KDIR、生成头文件和 `Module.symvers`，以及真实目标配置下的 `.ko` 编译/modpost、KPM 动态 load/unload、Hook 压力测试。没有进行 Fastboot、刷写、分区写入或真机启动。


## 17. 2026-11-10：当前 HEAD 的最新 Linux kptools 真实 Boot 复测

- 当前 HEAD：`26dc2e1bf4acfb9f605c18751f59a6787f6c71a8`（map-hole/PAC 扫描边界契约）。
- 最新相关 Actions：
  - Linux Host + 全量源码契约：Run `42678135670`，success。
  - GCC 14.2 ARM64 KPIMG：Run `42678135541`，success。
  - Windows kptools：Run `42678135438`，success。
- 从 Host Run 下载的 `kptools-linux-x86_64` SHA-256：`2b5cca0c94abc9826c8f737b974d11d8816e10c91ff5b40f32e2b5615a1979a7`。
- 资料库原始 `boot.img` SHA-256：`c47e94f64696fe70de11ea26cda4a3e0e6e025e581e7a96b95f1d975c9fe7cd5`；解压内核 Image 47,517,708 bytes，SHA-256 `345bfab8217669cb84ed004916efea4fae06e6b169c70e1be2ec9ac3ad4f093e`。
- 用当前 HEAD 的 Host 二进制执行 `kptools -d -i kernel`，退出码 `0`；实际导出 107,961 条符号，与 `kallsyms_num_syms=0x1a5b9` 精确一致。
- Token Table `0x01e4bd00`；Token Index `0x01e4c100`；Markers `[0x01e4af00, 0x01e4bc30)`；Names `0x01cef600`；Addresses `0x01c1c700`；kernel base `0xffffff8008080000`。
- `vectors` 导出地址 `0x00002800`；`pid_vnr` 的 CFI stub/veneer 校验成功，跳转目标 `0x0011bc10`，指令 `0xd5384108`，识别为 SP_EL0 读取路径。
- 日志中的候选回退警告对应不匹配候选被拒绝后继续尝试；最终候选通过精确 symbol count、vectors 和 pid_vnr 验证。没有出现工具崩溃或非零退出。
- 以上是当前 HEAD 对原始 Boot 解压内核的真实离线 Kallsyms 测试，不是设备启动或 APatch 初始化测试。没有使用 Fastboot、没有刷写、没有写设备分区。


## 18. 2026-11-10：当前 HEAD 的 KPIMG 注入与二次解包复核

- 使用当前代码 HEAD `26dc2e1bf4acfb9f605c18751f59a6787f6c71a8` 对应的 Linux Host kptools 和 GCC 14.2 KPIMG artifact；KPIMG SHA-256：`45aa42ba2ef29ad9d666652a0cba1765790b79270994c058bea0cd67300fab02`，版本 `0xD0A`。
- 对资料库原始 Boot 的工作副本执行 `kptools -p`，命令正常完成；自动 repack 生成 `y73s-head26dc-offline-patched.img`，大小仍为 100,663,296 bytes，SHA-256：`3c0a3bae0aa1c0bd8e7173cda93f5762c7ba85dbd78d2c95844fc81fd98ace6f`。
- 注入日志确认：非 GKI；map anchor 为 `tcp_init_sock`，偏移 `0x019352c4`；map start `0x019352d0`，保留区 `0x1000`；KPIMG 区域从解压内核偏移 `0x02d52000` 开始，长度 `0x4a720`；映射 NOP 同步范围 `0x2000`。
- 注入过程找到 `memblock_reserve/free/mark_nomap`、`memblock_find_in_range`、`memblock_virt_alloc_try_nid_nopanic`、`paging_init`、`rest_init` 等关键符号；日志提示 `kernel_init` 不存在且 KPM event timing degraded，`report_cfi_failure`、`__cfi_slowpath_diag`、`avc_denied` 也未找到。这些缺失项需继续作为运行时兼容性风险跟踪，不得忽略或宣称功能完整。
- 对输出 Boot 再次执行 `kptools unpack` 成功，解压内核大小 47,826,848 bytes，SHA-256：`9d1a17bbff064ca23f4dbc17fa94ccdb5f39fecbfad1e8503764bcb963b33486`；再执行 `kptools -d` 退出码 `0`，仍精确解析 107,961 个符号，`vectors`、`pid_vnr` 与 kernel base 均与原始内核一致。
- 从输出内核偏移 `0x02d52000` 读取到完整 `0x4a720` 字节 KPIMG 区域；嵌入区域前 65 bytes 与构建 KPIMG 完全相同，整段有 106 bytes 不同，符合工具对内嵌 superkey/key 字段的处理；不能称为逐字节原样嵌入。
- repack 日志明确提示：AVB metadata/footer 字节被保留并调整 offset，但没有重新计算 boot partition digest 或 AVB signature。因此该输出**不是 AVB-verified 镜像**，没有尝试设备启动或刷写。
- 原始 Boot 资料库文件未修改；全过程没有 Fastboot、没有设备分区写入、没有真机启动。
- 将原始与注入后解压 Image 的共同前缀逐字节比较：仅 4 bytes 不同，分别位于 ARM64 Image 入口分支指令（更新为跳入 KPIMG 入口区域）和 Image Header 的 `image_size` 字段；map anchor 区间 `[0x019352d0, 0x019372d0)` 与原始内核逐字节一致。KPIMG 作为新增尾部区域附加，没有覆盖该 map anchor 附近的原始函数代码。
- 对二次解包后的 raw kernel 执行 `kptools -u` 成功，输出大小恢复为 47,517,708 bytes；SHA-256 与原始解压 Image 完全一致（`345bfab8217669cb84ed004916efea4fae06e6b169c70e1be2ec9ac3ad4f093e`），逐字节比较也完全相同。这证明本轮 KPIMG 注入/卸载在 raw kernel 副本上完成精确离线往返；不改变 AVB 摘要不匹配的结论。
- 独立重算原 Boot AVB HashDescriptor（原 salt + descriptor 的 17,618,944-byte payload）：原始文件仍匹配原摘要 `36a3d398…`；注入输出得到 `c359f2c9…`，与原摘要不匹配。再次确认输出不可视为 AVB-verified，且本轮没有尝试绕过设备端验证。

### 该轮结论

当前 HEAD 已完成：Host/Linux、GCC 14.2 KPIMG、Windows 三条 CI；原始 Boot Kallsyms 全量离线解析；当前 KPIMG 对原始 Boot 副本的离线注入、repack、二次 unpack 和 Kallsyms 再解析。仍未完成目标 4.14.141 KDIR 的真实 `.ko` 编译/modpost、KPM 动态 load/unload、Hook 并发压力测试和设备端启动/APatch 初始化。


## 19. 2026-11-10：重新检索匹配的 MT6853 / PD2031 KDIR

### 找到的源码候选

1. `realme-kernel-opensource/realmeV5_AndroidQ-kernel-source`
   - Makefile：Linux `4.14.141`。
   - `k6853v1_64_6360_defconfig` 明确设置 `CONFIG_MACH_MT6853=y`、`CONFIG_MTK_PLATFORM="mt6853"`、`CONFIG_ARCH_MTK_PROJECT="k6853v1_64_6360"`、`CONFIG_LTO_CLANG=y`、`CONFIG_CFI_CLANG=y`，DTB overlay 名也为 `mediatek/k6853v1_64_6360`。
   - 仓库唯一提交时间为 2020-09-27；而原始 Y73s Boot banner 显示内核构建时间为 2022-02-15。公开 defconfig 也没有证明与 Boot 内嵌完整 .config 完全相同（例如 Boot 有 `CONFIG_CFI_CLANG_SHADOW=y`、`CONFIG_MODVERSIONS=y`，且 overlay 名带 `_PD2031`）。这是很接近的 4.14.141/MT6853 平台参考，但不能认定为精确 KDIR。
   - 链接：https://github.com/realme-kernel-opensource/realmeV5_AndroidQ-kernel-source

2. `vivo-source-mirror/Y53s`
   - 含 `k6853v1_64_6360_defconfig_PD2031`，配置的 MT6853 / project 名与 Y73s 对应，具有较高平台参考价值。
   - 但该仓库 Makefile 是 Linux `4.14.186`，比 Boot 的 `4.14.141+` 新 45 个 patchlevel；不能用它的生成头文件或 Module.symvers 声称兼容当前 Boot。
   - 链接：https://github.com/vivo-source-mirror/Y53s

3. `R0rt1z2/android_kernel_huawei_franklin`
   - Makefile 是 Linux `4.14.141`，且有完整的 MT6853 config 样本。
   - 但配置启用了 `CONFIG_HUAWEI_KERNEL`、`CONFIG_KALLSYMS_ALL=y`，项目名为 `k6853v1_64`，不是目标 Boot 的 `k6853v1_64_6360` / `KALLSYMS_ALL=n`；不是精确 KDIR。
   - 链接：https://github.com/R0rt1z2/android_kernel_huawei_franklin

3. `R0rt1z2/android_kernel_huawei_franklin`（branch `harmony-os-2.0`）
   - Makefile 为 Linux `4.14.141`；存在 `k6853v1_64_6360_defconfig`，其配置设置 `CONFIG_MACH_MT6853=y`、`CONFIG_MTK_PLATFORM="mt6853"`、`CONFIG_ARCH_MTK_PROJECT="k6853v1_64_6360"`、`CONFIG_LTO_CLANG=y`、`CONFIG_CFI_CLANG=y`，DTB overlay 名也为 `mediatek/k6853v1_64_6360`。
   - 该分支导入提交日期为 2021-09-26，提交说明为从 `JFRLM-AN00a_02_HM_opensource.tar.gz` 导入。它是目前发现的最接近“同 Linux patchlevel + 同 MT6853 board/project”的源码候选。
   - 但其来源是 Huawei 开源包，不是 Y73s/Vivo 原厂来源；当前只验证了 Makefile 和 defconfig，未对整树、结构体/驱动差异、生成配置及 Module.symvers 做同一性验证。只能作为静态比较候选，不能直接当成已确认 KDIR。
   - 链接：https://github.com/R0rt1z2/android_kernel_huawei_franklin/tree/harmony-os-2.0

### 当前判断

- 已找到同版本、同 SoC、同板级命名的 4.14.141 源码候选（Huawei 开源包），以及较老的 Realme 4.14.141 和较新的 Vivo 4.14.186 参考；仍没有可证明对应 2022-02-15 Y73s 原厂构建的源码提交、生成头文件和 `Module.symvers`。
- 不会拿 4.14.186 或 Huawei/Realme 不完全匹配的源码生成 `.ko` 并声称可加载；也不会把近似 defconfig 当成原始完整配置。
- 下一步优先比对 Realme V5 4.14.141 候选与 Y73s Boot 的驱动目录、关键结构体/函数、Kbuild 和完整配置差异；在确认源码基线前继续只做静态审计和 Host/KPIMG 离线测试。


## 20. 2026-11-10：对照上游 vivo Y73s / KernelPatch #189 故障记录

- 找到上游 KernelPatch issue #189，设备、内核 banner 和构建时间与当前资料库 Boot 完全对应：vivo Y73s / PD2031，Linux `4.14.141+`，Clang 9.0.3，`#1 SMP PREEMPT Tue Feb 15 12:32:17 CST 2022`。该记录报告旧 kptools 0.12.0 虽然显示 patch done，但 Manager Authentication Failed，连接 Wi-Fi 后 crash。
- issue #189 旧日志的 Kallsyms 结果为猜测符号数 `0x1a2bc`、`vectors=0x0032f800`、`pid_vnr=0x01846128`、kernel base `0xffffff8008153b00`，并出现 `mismatch relo applied`。这些正是不能接受的近似候选。
- 当前分支对同一份原始 Boot 的离线结果为精确 `kallsyms_num_syms=0x1a5b9`、`vectors=0x2800`、`pid_vnr=0x01912460`、kernel base `0xffffff8008080000`；`pid_vnr` 入口 veneer 跳转至 `0xd5384108`（SP_EL0 读取），且真实导出符号数精确匹配。这证明当前严格 Kallsyms 路径已纠正 issue #189 中的错误符号定位问题；但不证明 Wi-Fi crash、Manager 鉴权或所有 Vivo 安全模块问题已解决。
- issue 评论建议应用未合并的 KernelPatch PR #208（严格 Kallsyms 启发式）并回退 PR #225（PAC/map-area NOP 修改）。当前分支已经实现 PR #208 的核心 fail-closed 行为，并加上边界检查；PR #225 类 PAC 扫描仅在 `is_gki=true` 路径运行。原始 Y73s Boot 的注入路径判定为 non-GKI，因此不会执行该 PAC NOP 分支；本轮实测 map anchor 的 0x2000 字节同步区域与原始内核逐字节一致。
- 另查到作者的 `vivo-4.x-kernel-autopatch` 将 `do_mount_check` 作为**可选 Magisk 兼容补丁**，并明确部分设备不需要；mount fix 也被提示可能导致 boot failure。原始 Y73s kernel 在 `0x01b2944c` 处命中其 9-byte `do_mount_check` 数据模式，但本轮没有修改它。该二进制补丁不是 Kallsyms 修复，也没有证据证明 APatch 必须应用，禁止因搜索命中就自动写入。
- 下一阶段重点应转向 APatch/KPM 初始化后可能触发的 Vivo 安全模块交互与 Wi-Fi crash 根因；需要可复现的启动日志 / dmesg 或匹配 KDIR 后的动态测试。继续保持离线分析，不刷写设备。

参考：
- KernelPatch issue #189：https://github.com/bmax121/KernelPatch/issues/189
- 严格 Kallsyms PR #208：https://github.com/bmax121/KernelPatch/pull/208
- PAC/map-area PR #225：https://github.com/bmax121/KernelPatch/pull/225
- Vivo 4.x autopatch：https://github.com/4accccc/vivo-4.x-kernel-autopatch


## 21. 2026-11-10：修复 Token Table 游标后，用 CI 新二进制复测原厂 Boot

### 构建产物与输入完整性

- Linux kptools CI：Run `42678135670`，Commit `26dc2e1bf4acfb9f605c18751f59a6787f6c71a8`，两个 jobs（Host build、全源码 contract audit）均 success。
- GCC 14.2 KPIMG CI：Run `42678135541`，同一 commit，success。
- Windows CI：Run `42678135438`，同一 commit，两个 jobs 均 success。
- Linux kptools artifact SHA-256：`2b5cca0c94abc9826c8f737b974d11d8816e10c91ff5b40f32e2b5615a1979a7`，与 artifact 内 `SHA256SUMS` 一致。
- 从资料库重新取得原始 `boot.img`，SHA-256 为 `c47e94f64696fe70de11ea26cda4a3e0e6e025e581e7a96b95f1d975c9fe7cd5`，与此前基线一致。
- 使用这次 CI 的 kptools 解包，得到 47,517,708-byte ARM64 Image；SHA-256 `345bfab8217669cb84ed004916efea4fae06e6b169c70e1be2ec9ac3ad4f093e`，与原始解压内核基线一致。

### 最新二进制真实镜像解析

执行 `kptools -d -i kernel`，退出码 0。结果：

| 项目 | 实测值 |
|---|---:|
| Token Table | `0x01e4bd00` |
| Token Index | `0x01e4c100` |
| Markers | `[0x01e4af00, 0x01e4bc30)`，count `0x1a5` |
| Names | `0x01cef600` |
| Num Syms 位置和值 | `0x01cef500` / `0x1a5b9` |
| vectors | `0x00002800` |
| pid_vnr | `0x01912460` |
| kernel base | `0xffffff8008080000` |

- 独立统计 dump 中的符号行数为 107,961，与 `0x1a5b9` 完全相等。
- `pid_vnr` CFI stub 分支跟随到 `0x0011bc10`；目标指令 `0xd5384108` 通过 SP_EL0 读取校验。
- 原始内核没有可用的 `linux_banner` Kallsyms 名称；严格 vector fallback 成功完成验证。
- Token Table 起点恢复为真实基线 `0x01e4bd00`，不再是先前错误候选 `0x01e4bd04`。本轮游标修复已在最新 Host CI 中包含回归模型检查，并通过真实 Boot 二进制复测。

### 日志警告的正确解释

- 日志中的 `find approximate kallsyms_offsets error` 表示相对 offsets 候选不适用，程序继续尝试绝对地址表；它本身不是最终失败。
- 前两个候选基址的估算符号数为 `0x1a2c6`，不能精确验证 `num_syms`，因此被拒绝并重试。
- 第三个候选基址得到精确 `0x1a5b9`，并通过 vectors / pid_vnr 语义校验。上述两个错误候选均 fail-closed，没有被采纳。
- `ARM64 relocations were applied before the absolute-address scan` 是提示必须执行精确符号数和 vector 检查；最终候选确实通过了这两项检查。

### 本轮结论与边界

**已确认：Token Table 游标修复、最新 Linux kptools 构建、真实 Y73s 原厂内核完整 Kallsyms dump 均通过。** 当前分支从“源码检查通过”推进到“CI 产物对真实原厂内核离线解析通过”。

本轮仅解包和读取原始 Boot / 内核副本，没有修改原始文件，没有运行 patch/unpatch，也没有执行 Fastboot、分区写入或设备启动。该结果不代表修改后的 Boot 通过 AVB，也不代表 APatch 已能在真机初始化。

后续仍应优先处理：精确匹配的 Vivo 4.14.141 KDIR 与 Clang 9.0.3 工具链、目标 `.ko` 编译/modpost、KPM load/unload 和 Hook 并发测试，以及原 issue #189 中 Wi-Fi crash / Manager authentication failure 的动态证据。


## 22. 2026-11-10：从原始 Image 内嵌 IKCONFIG 提取完整目标配置

### 提取结果

使用本轮 CI 构建的 Linux kptools 执行 `-f -i kernel`，退出码 0。成功提取内核内嵌的完整 Linux 4.14.141 配置：

- 配置起始偏移：`31,892,704`（`0x01e6a7e0`）。
- IKCONFIG 压缩数据长度：33,577 bytes；解压后的完整 `.config` 为 148,325 bytes、5,486 行。
- 已提取干净配置文件 `vivo-y73s-4.14.141-extracted.config`，SHA-256：`f70215f43982b627eac9021aca8f9f1c47035c0c97890bee73adabdb2ec3cb8d`。原始 `kptools -f` 控制台 dump（含偏移/长度头行）SHA-256：`d779e40924f251d5f0e17bd009b5e1030440da58dcd63af0c6a70f20bba9dd88`。
- 配置确认：`CONFIG_MACH_MT6853=y`、`CONFIG_MTK_PLATFORM="mt6853"`、`CONFIG_ARCH_MTK_PROJECT="k6853v1_64_6360"`、`CONFIG_LTO_CLANG=y`、`CONFIG_CFI_CLANG=y`、`CONFIG_CFI_CLANG_SHADOW=y`、`CONFIG_MODVERSIONS=y`、`CONFIG_KALLSYMS=y`、`CONFIG_NR_CPUS=8`、`CONFIG_PREEMPT=y`、`CONFIG_ARM64_4K_PAGES=y`、`CONFIG_ARM64_VA_BITS=39`。
- 设备树 overlay 配置名为 `mediatek/mt6853`；Boot banner 的实际编译器为 Clang 9.0.3，构建时间为 2022-02-15。

### 与最接近的公开 KDIR 候选比较

对照 `R0rt1z2/android_kernel_huawei_franklin` 的 `harmony-os-2.0` 分支：

- Makefile 确认 Linux 4.14.141。
- `k6853v1_64_6360_defconfig` 与目标的 MT6853、project 名、LTO、CFI、NR_CPUS、PREEMPT、DTB overlay 名等核心项目一致。
- 但该 defconfig 未显式设置目标配置中的 `CONFIG_MODVERSIONS=y`；候选 `init/Kconfig` 对 MODVERSIONS 没有默认启用，因此仅按该 defconfig 生成时不能假设模块版本 CRC 已启用。`CONFIG_CFI_CLANG_SHADOW` 虽未写在 defconfig 中，但候选 `arch/Kconfig` 明确在 `CFI_CLANG` 启用时默认设为 y，故这一项本身不构成差异。
- 更重要的是该树来自 Huawei 开源包，不是 Vivo Y73s 原厂源代码；源码来源、驱动差异、CFI ABI、导出符号 CRC 和生成头文件均未与目标 Boot 证明一致。

### 结论

现在已从真实 Y73s Boot 取得完整目标 `.config`，不再需要猜测板级配置。Huawei 4.14.141 树可作为静态比较与配置试验候选，但仍不能标记为精确 KDIR，也不能用它构建的 `.ko` 声称可在目标设备加载。

下一步应优先寻找 Vivo PD2031 原厂 4.14.141 源码；若仍无原厂树，再以这份提取出的完整配置对近似树做 Kconfig 可解析性和 ABI 差异审计，并明确保留来源不匹配风险。当前没有进行 `.ko` 编译、modpost 或设备加载。


## 13. 2026-11-10：公开 KDIR 候选源码核验（只读）

本轮继续寻找与原始 Y73s Boot 对应的 Linux 4.14.141 KDIR。没有把不同机型源码冒充目标源码。

### 找到的最接近公开候选

- 仓库：[realme-kernel-opensource/realmeV5_AndroidQ-kernel-source](https://github.com/realme-kernel-opensource/realmeV5_AndroidQ-kernel-source)
- Makefile 明确为 Linux 4.14.141。
- arch/arm64/configs/k6853v1_64_6360_defconfig 包含 CONFIG_MACH_MT6853=y、CONFIG_ARCH_MTK_PROJECT="k6853v1_64_6360"、CONFIG_LTO_CLANG=y、CONFIG_CFI_CLANG=y，并关闭 CONFIG_KALLSYMS_BASE_RELATIVE。
- 其 ARM64 Kbuild 对 Clang 使用 -mno-implicit-float、-fno-pic、-mabi=lp64；scripts/Makefile.modpost 明确包含 CONFIG_LTO_CLANG 模块的 .lto.o、modpost 与最终链接路径；include/linux/compiler-clang.h 在 LTO 配置下定义 __nocfi 为 no_sanitize("cfi")。
- 参考设备树 4accccc/android_device_vivo_pd2031 也将 PD2031 识别为 MT6853 / k6853v1_64_6360，但其当前 BoardConfig 使用预编译 kernel，不提供完整原厂 KDIR。

### 与 Y73s 原始 Boot 的差异与限制

- 候选仓库名义上是 Realme V5 内核源码，不是 Vivo Y73s 官方发布源码；相同 SoC / project 字符串 / Linux 版本只能证明它是有价值的 ABI 参考，不能证明 vendor tree 完全相同。
- 候选仓库的公开 defconfig 未显式列出 CONFIG_CFI_CLANG_SHADOW 或 CONFIG_MODVERSIONS；而 Y73s 原始 Boot 内嵌 .config 已确认启用 CONFIG_CFI=y、CONFIG_CFI_CLANG=y、CONFIG_CFI_CLANG_SHADOW=y、CONFIG_LTO_CLANG=y、CONFIG_MODVERSIONS=y。defconfig 缺项不等同于最终构建配置关闭，但差异必须用目标完整 .config 与构建输出解决。
- 当前未取得与这份 Boot 完全匹配的 Module.symvers、生成头文件、完整 .config 和 Clang/LLD 9.0.3 构建输出。因此不能用该候选直接宣告 Y73s LKM 编译兼容。
- 未找到可验证的 Vivo PD2031 官方完整内核源码下载包；公开的 vivo-4.x-kernel-autopatch 只是内核镜像补丁工具，不是 KDIR。

### 本轮结论

**KDIR 搜索有进展，但目标 KDIR 仍未获得。** Realme V5 4.14.141 源码保留为只读 ABI 比较基线，不接入 Y73s 目标构建、不生成或签发目标 .ko。

### 下一步

1. 以原始 Boot 的编译器版本、CFI shadow/LTO/MODVERSIONS 配置为比对基准，对 Realme V5 候选的 Kbuild、CFI 实现、模块加载器、导出符号与 MT6853 vendor 差异做逐文件差异审计。
2. 继续检查 Vivo 官方源码发布渠道及可验证的 PD2031 固件配套源码线索。
3. 只有取得匹配的 KDIR + .config + 生成头文件 + Module.symvers 后，才执行 make V=1 dry-run 和真实 kernelpatch.ko 编译/modpost。

全程只读 GitHub / 文档 / 本地离线文件；未连接设备，未执行 Fastboot、9008、刷写、boot/vbmeta 修改或分区写入。


## 14. 2026-11-10：Clang CFI bypass 失败时关闭 KPM（源码修复，待 CI）

### 问题

Y73s 原始 Boot 已确认启用 CONFIG_CFI_CLANG=y 与 CONFIG_CFI_CLANG_SHADOW=y。KPM 映像由 LKM 自己分配和管理，不经过 Linux 原生模块加载器，因此不会自动获得原生模块加载流程中的 CFI shadow 注册。当前 LKM 依赖 kp_bypass_kcfi() 对目标内核 CFI failure/slowpath 入口安装 Hook，允许经过生命周期管理的 KPM 回调地址继续执行。

旧实现有两个缺口：

- 多个 Hook 安装结果共用同一个 rc，后续 Hook 的结果会覆盖前面失败，导致函数可能错误返回成功。
- CFI bypass 安装失败后，kernelpatch_init() 只记录警告，仍继续调用 kp_kpm_init()，使 KPM 加载入口保持开放。

### 修复

- kp_bypass_kcfi() 分别检查 find_check_fn、report_cfi_failure 和 __cfi_slowpath_diag / __cfi_slowpath 的 Hook 结果，不再让后续结果覆盖早先错误。
- 只有实际成功安装 report_cfi_failure 或 CFI slowpath Hook，才认定 enforcing bypass 已就绪。
- 在 CONFIG_CFI_CLANG=y 时，如果没有任何 enforcing bypass 成功安装，则返回错误。
- 任何部分安装失败都会调用 kp_bypass_kcfi_exit() 回滚已经成功安装的 Hook，避免留下指向失败初始化路径的分支。
- kernelpatch_init() 在 CONFIG_CFI_CLANG=y 且 bypass 初始化失败时不再调用 kp_kpm_init()；KPM 管理 supercall 保持未初始化并返回 -ENOSYS。LKM 其余不依赖 KPM 的功能仍可继续初始化。
- scripts/verify_lkm_kpm_contract.py 增加 CFI Hook 结果、失败回滚和 KPM 初始化门控契约。

### 变更提交

- 8f6956c：跟踪 CFI Hook 安装结果并在部分失败时回滚。
- a8657b4：目标启用 Clang CFI 但 bypass 不可用时关闭 KPM 初始化。
- d27adf0：增加源码契约，防止失败处理回归。
- 7d3edec、43313de：修正新增诊断字符串的转义，保持 C 源码换行格式。

### 复查与状态

- 已重新从目标分支读取 secpass.c、core/init.c 和 verify_lkm_kpm_contract.py。
- 对 enforcing hook 跟踪、CONFIG_CFI_CLANG 必需条件、部分安装回滚、错误保留、KPM 禁用门控和成功路径初始化执行了 7 项独立结构检查，7/7 符合预期。
- 这些是源码结构检查，不是 Clang 9.0.3 目标 KDIR 编译，也不是运行时 CFI 测试。对应 GitHub Actions 尚未取得最终结果，当前标记为待 CI。
- 尚未修改 Boot、KPIMG、vbmeta 或任何设备分区；未连接设备，未执行 Fastboot、9008 或真机启动测试。

下一步：等待并检查本次 LKM 源码契约 CI；随后继续审计目标 4.14.141 CFI shadow ABI、LTO module link 和 MODVERSIONS CRC。未取得精确 KDIR 前，不把该修复描述为真机兼容已验证。


## 15. 2026-11-10：LKM 初始化失败回滚与 KPM 私有运行时清理

### 发现的问题

复查 Linux 模块初始化语义时发现，module_init() 返回错误不会调用 module_exit()。原先 kernelpatch_init() 在 CFI bypass 已安装后，如果 kp_supercall_install() 或 kp_sucompat_hook_init() 失败，会直接 return rc；这可能把 syscall/CFI Hook 留在内核里，而模块加载器随后释放 LKM 映像，形成跳转到已释放模块内存的风险。

此外，kp_kpm_init() 成功时可能分配一页 callback trampoline。若后续初始化失败，也必须在模块映像释放前释放这块私有运行时资源。

### 修复

- kernelpatch_init() 记录 CFI bypass、KPM runtime、supercall 和 sucompat hook 是否成功安装。
- 所有后续可失败的 Hook 初始化统一跳转到 err_unwind，按安装逆序回滚已安装的 supercall、sucompat、KPM runtime 和 CFI bypass。
- 调整初始化顺序：先完成 sucompat Hook，再安装 supercall。supercall 成为最后一个可失败的 Hook 安装步骤；其成功后只执行不返回错误的 manager 初始化和 rename-LSM Hook 设置，避免对外发布 supercall 后再发生 init 失败。
- 新增 kp_kpm_exit()，仅用于尚未对外发布 supercall、没有 KPM 可被加载的初始化失败路径：先清除 kp_kpm_ready，再恢复 callback trampoline 的 NX/BTI 权限并释放（若权限恢复无法验证则按既有策略保留内存），最后清空 trampoline、分配器和运行时函数指针。
- 在 scripts/verify_lkm_kpm_contract.py 中增加初始化失败回滚顺序、KPM 私有 trampoline 清理及 supercall 最后发布的契约检查。

### 本轮复查

- 从目标分支重新读取 init.c、module.c、module.h 和契约测试脚本。
- 对 KPM 初始化成功标记、sucompat/supercall 发布顺序、各 Hook 逆序清理、KPM ready 清零先于 trampoline 释放、运行时指针清理执行 10 项结构检查，10/10 通过。
- 已修正契约测试中的清理顺序断言，使其与当前实际回滚顺序一致。
- GitHub 当前提交状态 API 没有返回可用的 CI status/check 项；不能把结构检查当作 CI 或目标 KDIR 编译通过。

### 变更提交

- 09965cf：初始化失败时回滚已安装 Hook。
- 18b4f09、95ca578：声明并实现私有 KPM runtime 清理。
- eae35fc、58a6030：supercall 最后发布并跟踪 KPM 初始化成功状态。
- 9026f1f、a7cf8ae、aedfd15：增加并校正生命周期回滚契约测试。

### 边界

未进行 Clang 9.0.3 目标 KDIR 编译、modpost、真机加载或启动验证。没有修改 Boot、KPIMG、vbmeta 或设备分区；未执行 Fastboot、9008 或任何刷写操作。


## 17. 2026-11-10：Linux 4.14 模块命名空间宏兼容修复

### 发现

对照原始 Y73s Boot 的 Linux 4.14.141 配置与 LKM 模块元数据代码时，发现 init.c 在所有低于 6.13 的内核上无条件调用旧形式 MODULE_IMPORT_NS(...)。但模块符号命名空间机制是在 Linux 5.4 开发周期引入，不能假设 4.14 的 module.h 定义了该宏。若目标 4.14 头文件没有此宏，编译会在模块元数据处失败。

### 修复

- 将 MODULE_IMPORT_NS 调用整体放入 #ifdef MODULE_IMPORT_NS。
- 保留 6.13 及以上的字符串参数形式。
- 对定义了该宏但早于 6.13 的内核保留旧 token 参数形式。
- 对没有该宏的旧内核不生成 namespace import 元数据，避免把新内核 API 强加给 4.14。
- scripts/verify_lkm_kpm_contract.py 增加宏存在性门控与新旧参数形式检查。

### 复查

- 从目标分支重新读取 init.c 与 verifier。
- 5 项针对性检查通过：宏存在性保护、6.13 新参数形式、旧参数形式、回归脚本覆盖、原始 Boot 的 MODVERSIONS/LTO/CFI 配置记录。
- 此项是基于 Linux 模块命名空间 API 引入时间的源码兼容修复；尚未使用 Y73s 精确 4.14.141 KDIR 进行编译确认。

### 提交

- 9ba310a：guard module namespace import on legacy kernels。
- b0ea3fe：增加 legacy module namespace compatibility 契约测试。

### CFI/LTO/MODVERSIONS 审计边界

- 原始 Boot 的配置已确认同时启用 CONFIG_CFI_CLANG、CONFIG_CFI_CLANG_SHADOW、CONFIG_LTO_CLANG 和 CONFIG_MODVERSIONS。
- 当前仓库的 GitHub Actions workflow 运行 KPIMG、Host 工具与源码契约验证；它没有用 Y73s 目标 KDIR 构建 kernelpatch.ko，因此这些 Actions 成功不能证明 LTO module link、CFI shadow module registration 或 MODVERSIONS CRC 兼容。
- lkm/Kbuild 对 hook_engine.o 使用 -fno-lto，并对 hook_engine.o / secpass.o 设置局部 CFI 隔离；这些参数必须通过目标 Kbuild 的真实 V=1 命令和 Clang 9.0.3/LLD 9.0.3 链接结果核对，不能仅凭 Kbuild 文本推断最终编译参数。
- 仍缺少与 Boot 完全匹配的 KDIR、生成头文件、Module.symvers 和完整构建输出。MODVERSIONS CRC、模块 CFI metadata/shadow 注册及 LTO 混合对象链接均保持未验证。
- 没有修改 Boot、KPIMG、vbmeta 或设备分区；未连接设备，未执行 Fastboot、9008、刷写或真机启动测试。


## 18. 2026-11-10：CFI Hook 撤销结果必须可验证

### 发现的问题

kernel/base/hook.c 原有 unhook() 返回 void。内部 hook_uninstall() 如果恢复目标函数原始指令失败，只会取消 retire 标记并返回；调用者无法知道原始内核文本仍可能保留跳转到 LKM 替换函数的分支。

lkm/infra/secpass.c 原先在调用 unhook() 后无条件清零 Hook 地址和 backup 指针。若恢复失败，模块卸载可能释放替换函数所在的 LKM 映像，留下跳转到已释放内存的风险。

另外，hook() 在底层热补丁返回 -EUCLEAN 时会发布 Hook 记录并返回 -HOOK_PATCH_UNCERTAIN。调用方此前只在 hook() 返回成功时保存目标地址，可能遗漏需要回滚的不确定安装记录。

### 修复

- 新增 unhook_checked(void *func)，返回原始指令恢复结果；区分成功、无 Hook 记录（-ENOENT）、忙状态和底层恢复错误。
- 保留原 unhook() ABI，改为委托 unhook_checked()，避免影响其他既有调用者。
- CFI bypass 在每次 hook() 尝试前保存目标地址，包括返回不确定错误的路径；清理时用 checked API 处理。
- 只有 checked unhook 成功或确认不存在 Hook 记录时，才清零对应地址和 backup 指针；恢复失败时保留状态并返回错误。
- kernelpatch_init() 的失败回滚无条件检查 CFI Hook 清理结果。
- kernelpatch_exit() 在释放 LKM 映像前检查 CFI Hook 是否全部撤销；若恢复失败，使用 BUG_ON fail-closed，避免继续释放仍被内核文本引用的模块代码。该策略可能导致设备 panic，但比静默留下跳转到释放内存的分支更安全。

### 本轮结构复查

- 检查 checked unhook 调用底层 hook_uninstall 并向上传递错误。
- 检查旧 unhook API 委托到 checked 实现。
- 检查三个 CFI Hook 均使用 checked teardown。
- 检查失败安装（包括 patch uncertain）保留目标地址以便回滚。
- 检查清理失败不会清空 Hook 地址/backup。
- 检查 module_init 失败路径与 module_exit 均 fail-closed。
- 新增 scripts/verify_lkm_kpm_contract.py 回归契约覆盖以上行为。
- 重新读取六个相关源码/测试文件，执行 10 项独立结构检查，10/10 通过；这不是目标 KDIR 编译或故障注入测试。

### 变更提交

- 34ac599：声明 checked unhook API。
- 6473c5b：实现并导出 checked unhook。
- 4231844：追踪不确定安装并检查 CFI Hook 撤销结果。
- ef84703：更新 CFI teardown 函数声明。
- bc4fd3c、7f6d6bc：初始化失败和模块卸载时阻止带着未恢复的 CFI Hook 释放模块映像。
- e0993bf、ab98b30：增加并修正 checked teardown 回归契约。

### 验证边界

本轮是基于源码控制流的安全修复与结构检查；未取得 Y73s 精确 4.14.141 KDIR，未运行 Clang 9.0.3 模块构建、modpost、CFI shadow 运行测试或真机加载。fail-closed 分支尚未通过故障注入验证。没有修改 Boot、KPIMG、vbmeta 或设备分区；未执行 Fastboot、9008 或刷写。


## 21. 2026-11-10：收紧 LKM CFI 可信目标范围

### 发现

重新对照 Android common android-trusty-4.14/kernel/cfi.c 后，发现 lkm/infra/secpass.c 的 kp_target_in_module() 原先把整个 core_layout.size 及 init_layout 视为可信目标；6.4+ 分支还遍历所有 module memory types。这比 Android 4.14 CFI Shadow 实际登记范围更宽。

android-trusty-4.14 的 add_module_to_shadow() 只登记 core_layout.base 到 core_layout.base + core_layout.text_size 的代码页面。模块数据区不应因属于 THIS_MODULE 就被视为可信间接调用目标。

### 修复

- 4.14 至 6.3：只允许 core_layout.base 起始、长度为 core_layout.text_size 的可执行核心文本。
- 6.4+：只允许 THIS_MODULE->mem[MOD_TEXT]，不再遍历数据、只读数据等其他类型。
- 使用 target - base < size 做有界检查，避免上界加法溢出。
- 移除 init_layout 放行；只信任仍在模块 CFI 文本映射内的代码。

### 契约与复查

- scripts/verify_lkm_kpm_contract.py 新增 MOD_TEXT、core_layout.text_size 检查，并明确拒绝 MOD_MEM_NUM_TYPES、core_layout.size、init_layout。
- 重新读取 secpass.c 和 verifier；6 项源码结构检查全部通过（现代 MOD_TEXT、现代长度边界、旧内核 text_size、旧内核有界返回、verifier 覆盖 MOD_TEXT、verifier 拒绝宽范围）。
- 代码提交：8e56e9e（修复范围）、05d0896（增加测试）、bc77340（修正测试断言）。
- Android 4.14 对照源码：https://android.googlesource.com/kernel/common/+/android-trusty-4.14/kernel/cfi.c

### 验证边界

本轮是源码级范围修复与契约审计；没有目标 KDIR 编译、modpost、CFI Shadow 运行验证或真机测试。Y73s 精确 4.14.141 KDIR、生成头文件和 Module.symvers 仍未确认。没有修改 Boot、KPIMG、vbmeta 或设备分区。



## 22. 2026-11-10：修复 LKM KPM RELA 条目大小检查时序错误

### 发现

继续审计独立 LKM KPM ELF 装载器时，发现 `layout_sections()` 会把全部节的 `sh_entsize` 重置为 `~0UL`，随后只为需要装入 KPM 映像的 SHF_ALLOC 节写入镜像偏移。常规 `.rela.*` 节通常不是 SHF_ALLOC，因此其 `sh_entsize` 会保持为 `~0UL`。

但 `kp_apply_relocate_add()` 在布局完成后仍要求 `rsec->sh_entsize == sizeof(Elf64_Rela)`。这把已被内部布局算法复用的字段误当成原始 ELF 元数据，导致含标准 RELA 节的 KPM 在重定位阶段被拒绝。该问题位于加载主路径，属于功能阻断，不只是测试缺口。

### 修复

- 在 `setup_load_info()` 中、`layout_sections()` 改写节头之前，验证每个 SHT_RELA 节的原始 `sh_entsize == sizeof(Elf64_Rela)`，并验证 `sh_size` 是 RELA 项大小的整数倍。
- `kp_apply_relocate_add()` 保留节类型和长度整除检查，但不再读取布局阶段已被复用的 `rsec->sh_entsize`。
- 更新两个独立 LKM 回归契约：`verify_lkm_kpm_contract.py` 和 `verify_lkm_kpm_loader_contract.py`，要求原始元数据在 setup 阶段验证，并禁止 apply 阶段读取过期字段。

### 提交

- `5636873`：在 setup 阶段验证原始 RELA 元数据。
- `7dcd86a`：移除重定位阶段对已复用 `sh_entsize` 的错误检查。
- `7a9c854`：增加阶段边界回归契约。
- `ceb86ba`：同步主 LKM/KPM 契约。
- `ea913ae`：同步独立 LKM loader 契约。

### 验证状态与边界

- 已重新读取修改后的 `module.c`、`relo.c` 和相关 verifier，确认原始 RELA entry size / divisibility 在 setup 阶段检查，apply 阶段不再检查 `rsec->sh_entsize`。
- 中间 CI 运行曾因旧 verifier 仍要求 apply 阶段检查 `sh_entsize` 而失败；日志明确显示是测试契约过时。随后已更新该 verifier，并再次触发完整 Actions。
- 代码提交 `ea913aeef5fc20d27d7978dba3b041f40b7ab1c1` 对应的 Linux Host 构建与完整源码契约 Actions（Run `42780756358`）已成功，包含两个独立 LKM/KPM loader verifier。该提交的 Windows 与 GCC 14.2 KPIMG Actions 当时仍在运行；文档更新提交为 `bf6f3fff4dd8974a4622c4327f509cfc1db79c75`，其后续 CI 仍待确认。
- 该修复尚未通过真实 KPM 文件加载或畸形 ELF 测试；目标 Linux 4.14.141 KDIR 编译、Clang 9.0.3/LLD、MODVERSIONS、CFI Shadow 和真机测试仍未完成。
- 没有修改 Boot、vbmeta 或设备分区；未使用 Fastboot、9008 或刷写。


## 23. 2026-11-10：补强 ELF 保留节索引回归契约

### 审计复核

继续核对 KPM ELF 符号表时，确认 `setup_load_info()` 已拒绝超出节表范围的普通节索引、`SHN_XINDEX`，以及除 `SHN_UNDEF`、`SHN_ABS`、`SHN_COMMON` 外的保留索引。这样可防止后续 `simplify_symbols()` 把特殊索引误当作 `sechdrs[]` 下标。

这次没有发现新的 loader 代码缺陷；问题在于独立 loader verifier 只显式检查了 `SHN_XINDEX`，没有保护完整的保留索引拒绝规则。

### 改进

- 在 `scripts/verify_lkm_kpm_loader_contract.py` 增加断言，要求 setup 阶段拒绝 `SHN_LORESERVE` 以上不支持的符号节索引，同时明确保留三个已支持的特殊索引例外。
- 没有改变 ELF loader 的运行逻辑。

### 提交与验证边界

- 测试补强提交：`789388e4a80de1ea70f3e5abb5aa33df7500ae03`。
- 已确认提交 diff 仅增加该契约断言。
- 对应 GitHub Actions：Linux Host/offline audit、GCC 14.2 KPIMG、Windows 构建均已触发；本记录写入时仍在运行，结果待回查。
- 这是源码契约覆盖，不是畸形 ELF 实际加载测试，也不是目标 4.14.141 KDIR 编译或真机测试。


## 24. KPM ELF section 对齐边界补强（2026-11-10）

本轮继续检查独立 LKM KPM ELF loader 的输入边界，发现原有检查验证了 section 的 `sh_addralign` 必须为 0、1 或 2 的幂，但没有验证文件内 section 起始偏移是否满足该声明；同时，ELF section-header table 的 `e_shoff` 也没有显式验证其满足 `Elf_Shdr` 的自然对齐。

这会让格式不合规或恶意构造的 ELF 把 SYMTAB、RELA 等 typed table 放在不满足其声明对齐的位置。AArch64 对部分非对齐访问可能有硬件支持，但不能用这一点替代 ELF 输入格式约束和 C 语言对象对齐要求。

本轮修改：
- `elf_header_check()` 在访问 section-header table 前，拒绝不满足 `__alignof__(Elf_Shdr)` 的 `e_shoff`。
- `rewrite_section_headers()` 对非 `SHT_NOBITS` section 检查 `sh_offset` 是否满足其有效 `sh_addralign`；NOBITS 没有文件内容，不对其文件偏移套用此约束。
- 独立 loader contract verifier 增加上述两项回归断言，并移除此前重复的 RELA 元数据断言。

提交：
- `add39691e05352590df417d0743d71ca02192a50`：loader 输入对齐检查。
- `f66d00720c95c18b118a85fa40204d2e669e7fc6`：增加回归契约。
- `57c49a075f9f5d5f5734ff77432b910444ccf82c`：清理重复断言。

验证边界：
- 此项目前完成了代码与 verifier 的静态一致性复核；新提交触发的 CI 仍需等待最终结果。
- 这不是实际执行内核 loader 的 ELF fixture 测试，也不等同于真实 KPM 加载验证。
- Y73s 精确 4.14.141 KDIR、Clang 9.0.3 + LLD 9.0.3 LTO/MODVERSIONS 构建以及真机运行仍未验证。


## 25. AArch64 指令重定位低位对齐检查（2026-11-10）

继续复核 RELA 的指令重定位时发现：`reloc_insn_imm()` 会按 relocation 类型右移 `lsb` 位后编码立即数字段，但此前没有验证被丢弃的低位是否为零。这会把未对齐的 PC-relative 分支位移或缩放 load/store 地址静默向下截断，产生错误目标地址/位移，而不是拒绝不合法的重定位表达式。

已同时修复 LKM KPM loader 与 KPIMG loader：
- 在右移和编码前检查 `(u64)sval & ((1ULL << lsb) - 1)`。
- 低位非零时返回 `-ENOEXEC`，由现有 RELA 事务回滚路径恢复目标 section。
- 对 `lsb == 0` 的 ADR/ADD 等未缩放字段不增加额外约束。
- 对 branch/conditional branch/literal load 的 4-byte 位移以及 LD/ST scaled immediate 的自然对齐统一生效。

提交：
- `74479e10f04a8d366a817a2c5e74b2eb447c83ff`：LKM 对齐检查。
- `a2b2d8560fe1159291e41de82c7bcc8308ea1324`：KPIMG 对齐检查。
- `3b9082560d70c19daa9e93d6d11a6fabde7bc62c`、`a5a7f8b52db1e89c782420d2262df8b1df13f981`：两套 loader 的回归契约。

验证边界：
- 本轮修复针对 relocation 表达式中被移除的低位，避免静默截断；静态 verifier 和新 CI 仍需验证。
- 尚未使用实际 AArch64 ELF fixture 执行 relocation 函数，也没有真实 KPM 加载或真机运行结果。


## 26. AArch64 指令重定位可执行 Host 测试（2026-11-10）

本轮把此前仅有源码契约检查的指令重定位路径推进到可执行测试。复核时还发现 LKM 的 `reloc_insn_imm()` 在检查立即数溢出前就把编码后的指令写回 `place`；若后续返回 `-ERANGE`，当前重定位条目会留下局部写入。KPIMG 版本已先校验再提交，LKM 版本现已统一为先做对齐与范围验证、最后写回指令。

修改：
- `lkm/kpm/relo.c`：把指令写回移到溢出检查之后。
- 新增 `scripts/test_aarch64_reloc_insn_imm.py`：从 LKM 与 KPIMG 两份真实源文件中提取 `reloc_insn_imm()` 函数体，生成临时 Host C harness，以系统 C 编译器编译并执行。仅对 `do_reloc` 与指令 immediate encoder 使用最小 stub，实际执行两个 loader 的函数体。
- 覆盖三种场景：未对齐值返回 `-ENOEXEC` 且不写入；对齐且在范围内的值成功编码；超出字段范围返回 `-ERANGE` 且不写入。
- 在 Linux Host 离线审计 workflow 中加入该可执行测试，并在静态 verifier 中增加“溢出检查先于指令写回”的顺序断言。

提交：
- `72eb93bc354d183323383a41181f76446e6113b7`：修复 LKM 指令写回时序。
- `5c53b746e4203dc277deb01df957fe0f443eeb38`：新增 Host C harness。
- `ede8f263264067b4a96675eab15f42677ecae3c4`：CI 执行 harness。
- `910f7b59a75570abca177a6a5c78b7b40d2dc7b4`：增加原子写回顺序契约。

测试边界：
- 这是对两个真实函数体的 Host 执行测试，但 encoder 与地址计算使用 stub；没有覆盖 ELF section/symbol/RELA 解析、所有 relocation type 或目标内核环境。
- 新 CI 正在执行；需要等待日志确认三组 case 均通过。
- Y73s 精确 4.14.141 KDIR、Clang 9.0.3 CFI/LTO、MODVERSIONS 和真机运行仍未验证。


## 27. AArch64 数据重定位 Host 边界测试扩展（2026-11-10）

在指令立即数字段测试基础上，继续把同一 Host harness 扩展到两份 loader 的 `reloc_data()` 实际函数体。覆盖 PREL16 正负边界、ABS16 无符号上界、溢出失败不写入，以及不支持宽度失败不写入。测试 harness 对 `do_reloc` 使用确定性 stub，保留真实 `reloc_data()` 的范围检查与目标写入代码。

新增/调整：
- 测试脚本统一命名为 `scripts/test_aarch64_relocations.py`。
- 对 LKM 与 KPIMG 分别编译并执行 instruction/data 两组实际函数体。
- 数据重定位覆盖：PREL16 +32767 成功、+32768 拒绝、-32768 成功；ABS16 65535 成功、65536 拒绝；非法宽度拒绝。
- 所有拒绝用例均检查目标缓冲区保持原值。
- Linux Host audit workflow 已切换到新脚本名称。

提交：
- `0ae2ed0677eb6d5b3f773880075d1ca5f5d1742f`：扩展数据重定位可执行测试。
- `37ad0adc2de758610f4dfc296e686e9924082f9e`：采用统一脚本名。
- `a15f0c4592b8fba470316387d1f837bf7417ff02`：更新 CI 调用。
- `097084669f17a18ae7fdf7ec1d8a35f89ca65373`：删除旧脚本路径。

验证边界：本轮新增数据重定位用例的 CI 尚待执行确认；Host harness 的地址计算仍使用 stub，不覆盖完整 ELF/RELA 表驱动执行。


## 28. 数据重定位 Host 测试修正与 CI 结果（2026-11-10）

扩展数据重定位 harness 时，首轮 CI 暴露的是测试生成器自身问题（C enum 类型占位符未完整替换，随后修复 Python 拼接括号）；不是 loader 运行逻辑失败。修正后，最新 Linux offline audit run `42790713488` 已成功，日志确认：
- LKM 与 KPIMG 各自的 3 个 instruction relocation 用例通过。
- LKM 与 KPIMG 各自的 6 个 data relocation 用例通过。
- 新增 Host 测试之后，原有全部 source-contract verifier 也继续通过。
- 同一 run 的 Linux kptools 构建成功。

修正提交：
- `d53c272abce871b0b6d3bef697e301ba1b87bfd6`：补全数据 harness enum 替换。
- `88f2471c7cd9ffb8fb9a7cd8c1a61f6869b6d3cd`：修正替换作用范围。
- `feaa7285d3e99e43e18b0332a74a174e432ecb01`：修复 instruction harness 字符串闭合。

当前验证仍不等于完整 ELF/RELA 表驱动加载测试：`do_reloc` 和 instruction encoder 仍为 Host stub；尚未覆盖每一种 AArch64 relocation type、完整 ELF section/symbol 索引路径或 Y73s 内核运行环境。GCC 14.2 KPIMG 与 Windows 构建在本次状态记录时仍在运行。


## 29. KPM ELF Header / Section Table Host Fixture（2026-11-10）

### 本轮推进

此前 Host relocation harness 已实际执行两套 loader 的指令与数据重定位函数体，但尚未进入 ELF 输入解析阶段。本轮新增 `scripts/test_kpm_elf_headers.py`，从 `lkm/kpm/module.c` 提取并在 Host C harness 中执行以下真实函数体：

- `kp_elf_range_valid()`
- `kp_elf_string_valid()`
- `set_load_error()`
- `elf_header_check()`
- `rewrite_section_headers()`

测试使用内存中构造的 ELF64 little-endian AArch64 ET_REL fixture，覆盖有效 section table、非 ELF64 class、section-header table 非自然对齐、section-header table 越界、section string table 截断、普通 section 文件范围越界、非 2 次幂对齐、文件 section 偏移不满足对齐、section name 越界，以及 NOBITS 不应要求文件内容范围等场景。

### CI 接入

- Linux Host audit workflow 已增加执行 `python3 scripts/test_kpm_elf_headers.py`。
- 新增 harness 与 workflow 接入提交：`021d4b5b759059080f5395dbcc0ad226adc03452`、`a0bbb0f775c9a696808957dfed26f03181807b19`。
- 本文档提交后需要检查新 HEAD 对应的 Host workflow 是否实际创建 job，并查看测试日志；在日志确认前不将这些 fixture 标记为通过。

### 验证边界

本 fixture 执行的是当前 LKM KPM loader 中真实的 ELF header / section-table 检查函数体；它尚未执行完整 `setup_load_info()`、符号表解析、RELA 表遍历、`apply_relocations()` 或模块内存写入/失败回滚。尚未覆盖 KPIMG loader 对应解析器，也不是目标 Linux 4.14.141 KDIR 编译或真机加载测试。后续应继续扩展到符号/字符串表与 RELA 记录，并用真实 relocation table 驱动完整的验证路径。

安全边界不变：只修改仓库源码、脚本和文档；不连接设备，不使用 Fastboot，不刷写或写入设备分区。


### 29 节 CI 结果补记（HEAD `dbe199cc6922cefc0878e217d6b16a1d23cafae7`）

- Host harness 首轮因 Python 源文件中嵌入实际 NUL 字节而无法解析；修正为 C fixture 字符串转义后，第二轮暴露两项测试生成问题：C 字符串换行转义，以及原“越界”section fixture 的长度仍在输入镜像范围内。均已修正；这两轮失败均发生在测试 harness 生成/fixture 预期，不是 loader 源码执行失败。
- 最终 Linux offline audit Run `42791588659`：**success**。Job `Audit LKM KPM ELF loader source` 与 `build-kptools` 均成功。
- 最终 harness 日志确认 9 项 ELF header / section-table fixture 全部通过：有效 ELF64 AArch64 ET_REL、非 ELF64、section-header table 非对齐/越界、section string table 截断、section 数据越界、非法对齐、文件 section 偏移不对齐、section 名称越界，以及 NOBITS 不依赖文件内容范围。
- 同一 audit job 中，既有 LKM 与 KPIMG relocation instruction/data 共 18 项测试继续通过；所有既有 source-contract verifier 继续通过。
- 该 Host run 的 Linux kptools 构建和 artifact 打包也成功。

当前这一步可标记为：**真实 loader 的 ELF header / section table 检查函数体已由 Host C fixture 执行通过**。仍未覆盖完整 `setup_load_info()`、SYMTAB/STRTAB 全路径、真实 RELA section 遍历和多条 relocation 的整体事务回滚；不能将本结果扩大解释为完整 KPM ELF 加载测试。


## 30. KPM RELA 多记录执行与事务回滚 Host Harness（2026-11-10）

### 新增测试

新增 `scripts/test_kpm_rela_transaction.py`，从生产文件 `lkm/kpm/relo.c` 提取并执行真实函数体：

- `do_reloc()`
- `reloc_data()`
- `kp_reloc_write_width()`
- `kp_apply_relocate_add()`

Host harness 使用 ELF64 的 `Elf64_Shdr`、`Elf64_Sym`、`Elf64_Rela` 构造多条 RELA 记录，并将生产函数应用于内存目标段。指令编码辅助函数在此 harness 中使用 stub；真实指令重定位 helper 仍由既有 `test_aarch64_relocations.py` 单独执行。

### 覆盖结果

本轮 10 项检查全部通过：

1. 两条有效 ABS16/ABS32 RELA 记录成功写入正确值。
2. 第一条已写入、第二条遇到未知 relocation type，整个目标段恢复原样。
3. 第一条已写入、第二条 PREL16 溢出，整个目标段恢复原样。
4. 无效 symbol index 在任何写入前拒绝。
5. relocation offset/width 越界在任何写入前拒绝。
6. 指令 relocation 目标地址未对齐时，在写入前拒绝。
7. RELA 表大小不是条目大小整数倍时拒绝。
8. SHT_REL 输入不会被错误报告为成功。
9. 备份内存分配失败时目标段保持不变。
10. RELA 的 sh_link 与指定 SYMTAB 不匹配时拒绝。

测试特别保留 `rsec->sh_entsize = ~0UL`，模拟 layout 阶段已将该字段复用为私有偏移的状态，确认 apply 阶段不会再把它当作原始 ELF 条目大小。

### CI

- 新增脚本提交：`66bd4dcdd75dcc8457cb5f7cb764019435e2da29`
- Host workflow 接入提交：`4b03e9da391e352f7121aebf8e0a66f3530ec6f5`
- Linux Host audit run：`42792965262`，`Audit LKM KPM ELF loader source` job 已成功；日志明确列出以上 10 项 `[PASS]`。
- 同一 run 的 `build-kptools` job 当时仍在运行，待其结束后再记录整个 workflow 结论。

### 验证边界

本 harness 执行真实 `kp_apply_relocate_add()`，但仅覆盖该函数的多记录校验、数据重定位和目标段事务回滚；指令重定位函数在该 harness 中为 stub，另由单函数 harness 覆盖。它没有执行完整 ELF `setup_load_info()`、真实文件输入到最终模块映像的完整链路，也没有执行 KPIMG 的同等 RELA loader、精确 Y73s Linux 4.14.141 KDIR 编译或真机加载。


## 31. 完整执行 setup_load_info() 的 Host ELF Fixture（2026-11-10）

### 新增测试

新增 `scripts/test_kpm_setup_load_info.py`，从生产 `lkm/kpm/module.c` 提取并执行真实函数体：

- `elf_header_check()`
- `rewrite_section_headers()`
- `kp_elf_range_valid()` / `kp_elf_string_valid()`
- `find_sec()`、`get_sh_base()`、`get_sh_size()`
- `set_load_error()`
- `setup_load_info()`

使用内存中的 ELF64 AArch64 ET_REL fixture，实际走过 section-name table、KPM init/exit/info sections、SYMTAB/STRTAB、symbol name、symbol section index、RELA 元数据的验证顺序。仅 `get_modinfo()` 用固定返回值 stub；本测试不声称覆盖 KPM info tag 的字符串解析实现。

### 覆盖结果

13 项测试全部通过：

1. 合法 KPM metadata、SYMTAB/STRTAB 和 RELA 元数据被接受。
2. SYMTAB `sh_entsize` 错误拒绝。
3. SYMTAB `sh_size` 不是符号条目整数倍拒绝。
4. SYMTAB link 指向非 STRTAB 节拒绝。
5. 符号名偏移超出 STRTAB 拒绝。
6. 符号名在 STRTAB 剩余范围内没有 NUL 终止符拒绝。
7. 普通符号 section index 越界拒绝。
8. `SHN_XINDEX` 拒绝。
9. 不支持的 reserved symbol section index 拒绝。
10. RELA `sh_entsize` 错误在 layout 前拒绝。
11. RELA `sh_size` 不是条目整数倍在 layout 前拒绝。
12. SYMTAB 的 STRTAB link 越界拒绝。
13. 多个 SYMTAB 拒绝。

### 测试修正记录

首轮 Host fixture 发现测试辅助函数错误地用 `strstr()` 查找以 NUL 开头的 ELF section-name table，无法遍历首个空字符串之后的名称。已将 fixture 名称查找改为按 NUL 分隔条目逐项遍历。此前 Host 编译器对 ELF section count 比较产生的 host-only `-Wtype-limits` 警告也已通过测试编译参数处理。以上是 harness 自身问题，修正后生产 parser 的 13 项 fixture 均通过。

### CI

- 测试脚本：`a58585cee56b860a945865c086b223c908100fb0`
- fixture 修正：`6ce113939620c9c9ee04a673310850c4623f6949`、`9c15e18b0c5a8417c49a52684858158b7052f3bc`、`53a569243b01d6449c48867bd86aa260f00021c9`、`f8f72faf0c8388fc542cd7273d14fb75ed383017`
- workflow 接入：`f05d89245b4acc3d426cb6ac3b7d1044ae02d6b7`
- 最新可确认 Host audit run：`42793489625`，`Audit LKM KPM ELF loader source` job 成功，日志明确输出 13 项 `[PASS]`；同一 run 的 `build-kptools` job 当时仍在运行，需另行确认整体 workflow 结束状态。

### 验证边界

这一步执行了真实 `setup_load_info()` 解析路径（`get_modinfo()` 除外），但仍是构造的 ELF fixture，不是实际第三方 KPM 文件，也未执行后续完整布局、符号简化、真实 ELF 到可执行映像的全链路。尚未覆盖 KPIMG 对应解析器、精确 Y73s Linux 4.14.141 KDIR 构建或真机加载。


## 32. LKM / KPIMG 符号地址转换边界一致性（2026-11-10）

### 审计发现与修复

对照两套生产 `simplify_symbols()` 后发现，LKM 版本已有 ET_REL 符号节内范围、符号 extent 和运行时地址加法溢出检查，而 KPIMG 版本此前直接执行 `secbase + st_value`，缺少相同保护。

已在 `kernel/patch/module/module.c` 补齐 KPIMG 检查：
- 拒绝超出 ELF section table 的普通符号节索引，避免直接越界访问；
- 拒绝 `st_value` 超过所属节大小；
- 拒绝 `st_size` 超出所属节剩余范围；
- 拒绝 `secbase + st_value` 的 unsigned long 加法溢出。

同时在 LKM 版本增加同等的函数入口 section-index 防御检查，使两个实现都不依赖调用者永远先执行 parser 校验。

### 新增 Host 测试

新增 `scripts/test_kpm_simplify_symbols.py`，直接提取并编译执行两套生产函数，而不是复制重写其逻辑。覆盖用例共 11 类，并分别对 LKM、KPIMG 执行：
1. 普通定义符号 offset 转换为运行时地址；
2. 零长度符号恰好位于节末尾；
3. 符号起始 offset 超出节范围；
4. 符号 extent 跨越节末尾；
5. 运行时地址加法溢出；
6. SHN_ABS 保持绝对值；
7. LKM 兼容符号表 / KPIMG 符号表解析；
8. LKM kallsyms fallback / KPIMG 符号解析；
9. 未定义符号找不到时拒绝；
10. SHN_COMMON 拒绝；
11. 无效 section index 拒绝。

### CI 状态

- KPIMG 生产修复提交：`c454dea92023a7781aef3f9a7608fdd4ccbc0fc1`
- LKM 入口防御提交：`ac5d68b34815ed4e69c5fc3fe65a8775163d5d21`
- Host 测试提交：`645a3472fff12ec0642a54323ec57aa096015110`
- workflow 接入提交：`a87a0eb677d16a5ac253c495f8bf36e7d262d980`

### CI 结果与测试夹具修正

- 首轮 Host run `42795243926` 的符号测试失败，日志确认是 fixture 将 SYMTAB 的 `sh_size` 设置为整个三元素数组大小，却只初始化一个待测符号；后续空符号被生产代码按 ELF 语义解析，造成预期不符。该失败属于测试夹具，不是生产函数失败。
- 已将 fixture 的 SYMTAB 大小改为两个条目（空符号 0 + 一个待测符号），修正提交：`21c8fd921c5155aaafd09ea92b7ef7a8d1f98162`。
- 修正后 Host run `42795362396`：`Audit LKM KPM ELF loader source` 成功，`build-kptools` 成功；日志确认两套生产 `simplify_symbols()` 均执行完成，11 类用例分别对 LKM、KPIMG 通过。
- 修正提交对应的 GCC KPIMG 构建 run `42795362369` 已完成编译和审计步骤，最后的 workflow 收尾状态当时仍在进行；Windows 构建另有对应任务，待最终状态确认。

此项验证是 Host 合成符号表 + 真实函数体执行，并非完整 ELF 端到端加载。它不是 Y73s 真机验证，也不替代精确 Linux 4.14.141 KDIR 编译。


## 33. 双加载器 section layout 与最终映像复制 Host Fixture（2026-11-10）

### 新增测试

新增 `scripts/test_kpm_layout_copy.py`，直接从 LKM 与 KPIMG 生产源码提取并执行：
- 两套 `get_offset()`；
- 两套 page-alignment helper；
- 两套 `layout_sections()`；
- 两套 `move_module()`。

合成 ELF fixture 包含 executable、RO、RW、NOBITS 和 `.kpm.info` 节，检查最终模块大小、text/RO 边界、节偏移、PROGBITS 内容复制、NOBITS 零初始化、init/exit 入口地址，以及搬迁后 name/version 指针是否仍指向新映像中的 metadata。

另覆盖：
1. 非 2 次幂 section alignment 被两套 loader 拒绝；
2. 最终目的映像复制范围越界被拒绝；
3. executable allocation 失败返回错误。

### Harness 修正

首轮编译发现提取函数后，测试没有同步改写被提取的 helper 调用名；已在 fixture 中显式映射到各自的 LKM/KPIMG helper。之后发现两套实现对非法 alignment 返回的负 errno 不同（LKM 将 helper 错误映射为 `-EOVERFLOW`，KPIMG 返回 `-ENOEXEC`），测试改为验证双方均 fail-closed，不强求内部 errno 一致。这些是 Host harness 的适配问题，不是生产代码故障。

### CI

- 测试脚本提交：`e36d099a1b0f4e98606e7be5455bbe1f4252d0c6`
- workflow 接入提交：`67251633381239cc22adbc686fddcc25853ea98d`
- helper 调用映射修正：`7d0d8793e05743e0e990141aa90929a9fa6d09dd`
- errno 断言修正：`50a3a8a8fefd2eb26b7651a51a3840686993d247`
- Host run `42795923519` 的 `Audit LKM KPM ELF loader source` job 成功；日志明确输出 LKM、KPIMG layout/copy 及 3 类失败路径的全部 `[PASS]`。同一 run 的 `build-kptools` 最终也成功完成编译、打包和 artifact 上传。
- 符号转换 Host run `42795362396` 成功；GCC KPIMG run `42795362369` 成功；Windows kptools 在 run `42795484540` 成功（该 Windows run 对应符号修复后的提交）。

### 验证边界

这是合成 ELF fixture 执行生产布局/复制函数，不等于任意真实 KPM 文件的完整端到端加载；尚未在精确 Y73s Linux 4.14.141 KDIR 编译，也未在 Y73s 真机加载。最新布局测试提交对应的 GCC / Windows CI 仍需单独确认。


## 34. KPIMG RELA 时序修复与元数据解析一致性（2026-11-10）

### 发现的生产问题

沿 KPIMG 的真实加载顺序审计发现，`layout_sections()` 会把所有节的 `sh_entsize` 改写为 `~0UL` 或映像偏移，但旧的 `apply_relocations()` 在布局后仍要求 RELA 的 `sh_entsize == sizeof(Elf64_Rela)`。标准非 alloc RELA 节因此会被错误拒绝。

修复方式：
- 在 `setup_load_info()`（布局前）检查原始 RELA `sh_entsize` 和 `sh_size`；
- 布局后的 `apply_relocations()` 不再读取被复用的 `sh_entsize`，仅保留条目整数倍检查；
- Host fixture 特意把 RELA 的 `sh_entsize` 改为 `~0UL` 后调用真实 dispatcher，确认合法 RELA 仍会派发。

同时补齐 KPIMG parser 与 LKM 的重要校验差异：
- section-name string table 必须首字节为 NUL；
- `.kpm.init` / `.kpm.exit` 必须存在、可执行且非空；
- `.kpm.info` 必须为非空 PROGBITS，且节尾 NUL 终止；
- 必需的 name/version 字段不得为空；
- symbol STRTAB 必须以 NUL 开头；
- 拒绝多个 SYMTAB。

双 SYMTAB fixture 首次发现：虽然已加入重复表检测，但旧循环在第一个 SYMTAB 后提前 `break`，导致第二张表永远不检查。已移除该提前退出，现由真实 parser fixture 回归覆盖。

### 新增 Host Fixture

新增 `scripts/test_kpimg_kpm_loader.py`，直接提取执行 KPIMG 生产函数：
- `elf_range_valid()`、`elf_string_valid()`；
- `get_next_modinfo()` / `get_modinfo()`；
- `find_sec()`、`get_sh_base()`、`get_sh_size()`；
- `rewrite_section_headers()`、`setup_load_info()`；
- `apply_relocations()`。

覆盖合法 metadata、错误 info section 类型/大小/终止符、非 executable init、空 name/version、坏 RELA 条目大小、坏 symbol STRTAB、多个 SYMTAB、布局后 RELA、未支持 REL、坏 target index 和错误 symbol-table link。

### CI 与修正记录

- KPIMG RELA / metadata 主修复：`68d7349a6cc13db574b460251a2fc1f8038f0324`
- KPIMG 多 SYMTAB 提前退出修复：`f73b49df9793ec290830f24841dc20a8c75218f0`
- KPIMG Host fixture：`cdcf00fa24851b7a22dc85bd39181a8b8bd05da0`
- fixture 断言修正：`d1dbddc679721704a523132814803614c6cfa842`
- source contract 更新：`eb0dc062ad8c7ad66a7767c71c4a9ba61a605655`
- workflow 增加 KPIMG 路径触发和 Host 测试：`fc87874b1f5ca94aeb70034c71eaef9ae5bc0396`、`ddfb429c69132532513ea4ff092c88209daab8be`
- Host run `42796685283` 的 `Audit LKM KPM ELF loader source` 与 `build-kptools` 两个 job 均成功；日志明确显示 KPIMG parser fixture 和“valid RELA still dispatches after sh_entsize is repurposed”通过，Linux kptools 编译、打包和 artifact 上传也成功。GCC 14.2 KPIMG run `42796648024` 成功。Windows 构建 run `42796685498` 在本次记录时仍在运行，待最终确认。

### 验证边界

本轮修复解决了 KPIMG 标准 RELA 在布局后被错误拒绝的问题，并补齐 parser 元数据校验；测试仍是合成 ELF Host fixture，不是实际第三方 KPM 的全链路加载。精确 Y73s Linux 4.14.141 KDIR 编译和真机加载仍未验证。


## 35. LKM 真正 modinfo 字符串解析与必需字段校验（2026-11-10）

### 新增覆盖

之前的 LKM `setup_load_info()` Host fixture 对 `get_modinfo()` 使用固定返回值 stub，因此并未执行生产 metadata 字符串解析器。本轮已移除该 stub，改为直接提取并执行生产：
- `next_string()`
- `get_next_modinfo()`
- `get_modinfo()`

fixture 的 `.kpm.info` 改为真实的 NUL 分隔 `name=fixture\0version=1.0\0` 内容，原有合法 KPM parser 用例现在真实经过 metadata 查找逻辑。

### 发现与修复

LKM 与 KPIMG 都会把 name/version 视为必需字段，但此前只检查查找结果是否为 NULL；`name=` 或 `version=` 会返回非 NULL 的空字符串指针并被接受。现已在两套 loader 中统一拒绝空 name/version。

新增 Host 用例分别验证空 module name 和空 module version 被真实 parser 拒绝。KPIMG fixture 同时覆盖这些输入。

### CI

- LKM 生产修复：`12d9f098dfdf7395c1583c2895f837819fb13204`
- LKM parser fixture 移除 stub 并接入真实 modinfo：`0836a340ac509d92d23741a23c344e691f7961f0`
- Host run `42796907050` 的 `Audit LKM KPM ELF loader source` job 成功；日志明确输出合法 metadata、真实 modinfo parser、空 name 和空 version 用例通过。该 run 的 `build-kptools` 当时已进入编译步骤，待最终确认。
- KPIMG GCC 构建 run `42796648024` 成功；Windows kptools run `42796647963` 两个构建/上传任务成功完成。

### 验证边界

这一步实际执行了 LKM metadata 字符串解析器，但仍使用合成 ELF fixture。没有替代真实第三方 KPM 端到端加载、精确 Y73s Linux 4.14.141 KDIR 编译或真机验证。


## 36. Y73s 4.14.141 ARM64 缓存 API / 模块链接兼容修复（2026-11-10）

### 目标证据核对

本轮不再只使用通用 4.14 假设，而是同时核对了资料库中提取的 Y73s 目标内核配置与 KALLSYMS：
- Linux/arm64 4.14.141，4 KiB page（`CONFIG_ARM64_PAGE_SHIFT=12`），39-bit VA（`CONFIG_ARM64_VA_BITS=39`），`CONFIG_PGTABLE_LEVELS=3`；
- `CONFIG_MODULES=y`、`CONFIG_MODVERSIONS=y`；
- `CONFIG_LTO_CLANG=y`、`CONFIG_CFI_CLANG=y`、`CONFIG_CFI_CLANG_SHADOW=y`；
- `CONFIG_KALLSYMS=y`，但 `CONFIG_KALLSYMS_ALL` 未启用；
- Clang banner 为 9.0.3。
- 目标 KALLSYMS 仍实际包含 `__flush_dcache_area`（偏移 `0x5084`）和 `flush_icache_range`（偏移 `0x4fb4`）。因此，即使 `KALLSYMS_ALL=n`，本目标的函数符号运行时查找仍有直接证据支持。

### 生产代码修复

对照上游 Linux stable `v4.14.141`：
- ARM64 `asm/cacheflush.h` 声明 `__flush_dcache_area` 与 `flush_icache_range`，但没有 `__flush_icache_range`；
- `arch/arm64/mm/flush.c` 导出 `flush_icache_range`；
- `__flush_dcache_area` 在 `arch/arm64/mm/cache.S` 实现，但未由该版本 `flush.c` 导出；
- `kernel/kallsyms.c` 将 `kallsyms_lookup_name` 以 GPL 符号导出。

原 LKM 旧缓存分支直接引用 `__flush_dcache_area`，并调用 4.14 不存在的 `__flush_icache_range`。前者会形成外部模块的未导出符号依赖，后者会形成声明/链接不兼容。

修复：
1. 旧 D-cache 路径改为通过 `kp_resolve_symbol("__flush_dcache_area")` 运行时解析，不再生成未导出符号的模块重定位；
2. 解析失败时 `kp_patch_memory_init()` 返回 `-ENOSYS`，在任何内存 patch 发生前 fail-closed；
3. 对原始汇编 D-cache helper 的间接调用封装在 `no_sanitize("cfi")` wrapper，避免对没有编译器 CFI 类型记录的汇编入口做无效间接调用检查；
4. 旧 I-cache 路径改用 4.14 已导出的 `flush_icache_range()`；
5. 更新 Kbuild 注释和新增 `scripts/verify_y73s_414_api_contract.py`，在 CI 检查旧 API 分支、未导出符号间接解析、CFI wrapper、I-cache API、版本门控和折叠 P4D 用法。

### 测试与 CI

- 生产修复：`42d1897f35f53afd38a561c4d1364813302eb81a`
- CFI wrapper：`9d8ee9588016b67c1a131cddb120e36ca562d693`
- 4.14 API contract：`f2e372d28515b41469ac3a83ba44eca93056d7cb`
- contract 断言修正：`fc3975aabca090aca7772e63501e33b16a4e898f`、`bdafa14b4f3b6bfb674beee3dfc664c55ae7388c`
- CI 接入：`215443687cafcba789c6517009bc384e5a651e7f`
- Kbuild 说明：`621bdb0420f1ee90760c928d40a07b2226d72501`
- 最新 contract 断言排除注释误报：`02f99cb7b0506f49fda5e7fe0893b39935715304`
- GCC KPIMG run `42801460895` 曾因 contract 测试把 C 注释中的 `__flush_dcache_area()` 误识别为直接调用而失败；已修正为先剥离 C 注释再检查。该失败是测试脚本误报，不是生产代码构建错误。修正后的 run `42801737368` 已成功：Arm GNU GCC 14.2 KPIMG 构建、完整 source contract、4.14.141 API contract、kptools headers / Linux kptools build 与 artifact 上传全部通过。Windows kptools 的同一 run job 在记录时仍运行中。

### 4.14 版本兼容核对中的更正

曾一度把 ARM64 4.14 的 P4D 当成不存在；进一步核对发现它由 `asm-generic/pgtable-nop4d.h` 折叠提供，`p4d_t` / `p4d_offset()` 在 4.14 仍有效。因此未按错误结论修改三处页表遍历代码。

### 未完成的目标构建门槛

目标配置启用了 `CONFIG_MODVERSIONS=y`、LTO 和 Clang CFI。要证明 LKM 对 Y73s 真正可装载，仍必须用同一份 4.14.141 vendor KDIR、生成头文件和匹配的 `Module.symvers`，在目标 Clang 9.0.3 / 对应 LLD 环境中完成完整外部模块编译与 modpost。当前资料库有 boot、提取配置和 KALLSYMS，但没有完整 vendor KDIR / `Module.symvers`；因此此项仍未通过验证，也不能由 Host 或 GCC KPIMG CI 替代。

上游 API 核对源：
- `https://github.com/gregkh/linux/blob/v4.14.141/arch/arm64/include/asm/cacheflush.h`
- `https://github.com/gregkh/linux/blob/v4.14.141/arch/arm64/mm/flush.c`
- `https://github.com/gregkh/linux/blob/v4.14.141/arch/arm64/mm/cache.S`
- `https://github.com/gregkh/linux/blob/v4.14.141/kernel/kallsyms.c`


## 37. 依据 Y73s 实际 KALLSYMS 校准 4.14.141 运行时符号后端（2026-11-10）

### 目标证据

本轮对资料库中的完整 \`vivo-y73s-kallsym-test(1).log\`（3,929,958 bytes）执行了按完整符号名精确匹配的离线扫描，而不是用 \`files.find\` 的子串结果推断符号存在或不存在。

实际存在的关键符号（地址为该 KALLSYMS dump 的 image-relative offset）：
- \`module_alloc\`：\`0x0192cb24\`
- \`module_memfree\`：\`0x019425e0\`
- \`vmalloc_to_page\`：\`0x01914870\`
- \`SyS_truncate.cfi\`：\`0x003cd6b8\`
- \`sys_truncate\`：\`0x019305cc\`
- \`__cfi_slowpath\`：\`0x002ddc00\`
- \`kallsyms_lookup_name\`：\`0x01922680\`
- \`kallsyms_on_each_symbol\`：\`0x019133d4\`
- \`__flush_dcache_area\`：\`0x00005084\`
- \`flush_icache_range\`：\`0x00004fb4\`
- \`stop_machine\`：\`0x019135b4\`

完整 dump 中没有以下精确符号名：
- \`init_mm\`、\`sys_call_table\`
- \`set_memory_x\`、\`set_memory_nx\`
- \`find_check_fn\`、\`report_cfi_failure\`、\`__cfi_slowpath_diag\`

### 适配结论与代码路径

该符号分布与 Y73s 的配置（\`CONFIG_KALLSYMS_ALL=n\`、\`CONFIG_CFI_CLANG=y\`、\`CONFIG_MODVERSIONS=y\`）吻合，并支持当前实现选择：
1. Hook 和 KPM 的 executable backend 应选择成对存在的 \`module_alloc/module_memfree\`，不能依赖 \`set_memory_x/nx\` 或隐藏的 \`init_mm\`。
2. 无 \`init_mm\` 的 patch address translation 使用 \`vmalloc_to_page()\` 处理 vmalloc/module_alloc 映射；该符号在目标 KALLSYMS 中存在。
3. 4.14 supercall 使用 \`SyS_truncate.cfi\` 函数体作为 inline hook 目标，不使用四字节 CFI jump-table alias。
4. CFI bypass 在 \`find_check_fn\`、\`report_cfi_failure\`、\`__cfi_slowpath_diag\` 不存在时回退到目标实际存在的 \`__cfi_slowpath\`。

为防止后续改动误用其他内核的符号假设，新增精简的目标符号 fixture 和 \`scripts/verify_y73s_414_kallsyms_profile.py\`；CI 会校验必需符号与预期缺失符号。fixture 是从目标完整 dump 提取的关键符号子集；本节的缺失符号结论来自对完整 dump 的精确扫描。

### CI

- 符号 fixture：\`314e9755beb8adb094a91a2726d28c3f3de5e40b\`
- profile verifier：\`0054a2e81b792a6fb57fb1b4e5e885bcfe7f58a5\`，正则修正：\`614a66acf851be48e111a2ea2131b52fea8aa921\`
- API contract 增强：\`e8a7935bfd3efb9466ef9b98f26854bf439b79ee\`
- CI 接入：\`e24aa4c876c58161fb23f370791942af0b26a17c\`
- GCC 14.2 KPIMG run \`42809197416\`：成功；日志确认 Y73s 4.14.141 KALLSYMS profile、no-init_mm 地址转换、Supercall ABI 和 CFI slowpath fallback 测试通过。
- 同一提交的 Windows build workflow run \`42809197330\`：Ubuntu KPIMG/kptools job 成功；Windows job 在本节记录时仍运行中。

### 未完成的验证门槛

虽然现在已用目标真实 KALLSYMS 校准了运行时解析路径，但 LKM 仍未在目标 vendor KDIR 上完成编译与 modpost。目标配置开启 \`CONFIG_MODVERSIONS=y\`、Clang 9.0.3 LTO/CFI；没有同一份 4.14.141 vendor KDIR、生成头文件和匹配的 \`Module.symvers\`，就无法证明外部模块 CRC 与 CFI/LTO 链接兼容。Host、GCC KPIMG 和源代码 contract 均不能替代这一项。没有进行真机加载或设备操作。


## 38. Y73s 4.14.141 Supercall / Hook 运行时链路复核（2026-11-10）

### 当前分支与 CI 核对

- 当前分支 HEAD：`d1f116d0720edf1fb84e5dff65e5fc2ca235d074`。
- GCC 14.2 Y73S KPIMG run `42809836646`：成功。
- Windows kptools run `42809836617`：成功。
- 本次只进行代码链路复核和状态文档校正，没有声称新增目标内核构建或真机验证。

### 4.14 Supercall 路径复核

逐段检查 `lkm/supercall/supercall.c`、`lkm/infra/syscall_table.c`、`kernel/base/hook.c`：

- 非 `CONFIG_ARCH_HAS_SYSCALL_WRAPPER` 分支使用 `SyS_truncate.cfi`，不依赖目标缺失的 `sys_call_table`。
- 4.14 handler 将 x0/x1 作为原始 truncate 参数，x1 低 16 位识别 supercall command，x2-x5 传递四个 payload 参数。
- inline hook 安装前设置 backend；安装失败时清除 backend；`-HOOK_PATCH_UNCERTAIN` 路径尝试 `unhook_checked()`，恢复失败 fail-closed。
- 卸载使用 `unhook_checked()`，恢复失败触发 fail-closed，不会静默清除仍可能生效的 hook 状态。

已有 `scripts/test_y73s_414_supercall_abi.py` 从生产 handler 提取真实函数体，Host 测试覆盖授权 dispatch、未授权 truncate passthrough、非法 command passthrough、缺失 trampoline fail-closed。

### Hook / executable memory 路径复核

- Y73s profile 中 `module_alloc` 与 `module_memfree` 均存在；4.14 ARM64 module allocator 作为 `PAGE_KERNEL_EXEC` 后端使用。
- 在 `init_mm` 不可解析且 4.14 没有 PTE_GP 的路径，hook runtime 仅接受成对的 module allocator/free backend；不会对 vmalloc 后端假定可执行权限。
- trampoline 的分支生成使用 x17；被搬迁的指令仍由 AArch64 relocation helper 处理。
- patch-memory 在没有 `init_mm` 时使用 direct-map / kernel-image `virt_to_phys()` 或 vmalloc/module 区域 `vmalloc_to_page()`；需要 `stop_machine` 才执行文本批量修改。目标 KALLSYMS profile 中包含 `stop_machine`、`vmalloc_to_page` 和 `__flush_dcache_area`。

### 验证边界与待办

以上是源码调用链复核 + 目标 KALLSYMS 存在性证据，不证明函数地址在运行时解析成功，也不证明 syscall entry 的 x2-x5 在目标 vendor 编译产物中实际保持到 hook trampoline。后续仍需：
1. 精确 vendor 4.14.141 KDIR + 生成头文件 + Module.symvers 的 Clang 9.0.3 外部 LKM 编译和 modpost；
2. 对 `SyS_truncate.cfi` 真实机器码进行反汇编，核对前四条被搬迁指令、入口 thunk 和 CFI 入口布局；
3. 目标 Clang 9.0.3 / LLD 9 CFI/LTO 模块链接；
4. 目标设备运行时验证（在用户明确要求设备操作前不执行刷写或设备操作）。

**本节没有把 Host ABI fixture、KALLSYMS 符号存在性或 GCC KPIMG 构建等同于 Y73s LKM 可加载。**


## 39. Y73s 4.14 sucompat 安装失败回滚与并发卸载加固（2026-11-10）

### 发现的生产代码问题

针对 Y73s 的 `prepare_binprm` 回退路径复核 `hook_wrap1()`、`hook_unwrap_remove()` 与 `kernelpatch_init()` 的完整生命周期，发现两个实际风险：

1. `hook_wrap1()` 在文本补丁不确定时可能返回 `-HOOK_PATCH_UNCERTAIN`，但原 `kp_hook_prepare_binprm()` 只在返回成功后记录目标地址和 backend。这样 init rollback 不知道存在可能已发布的 hook。
2. sucompat teardown 原先调用不返回状态的 `hook_unwrap()`，忽略 `hook_unwrap_remove()` 的 `-EBUSY`。若 transit reader 仍在执行，模块卸载可能在回调代码仍被引用时继续。

### 修复

- 在执行 `hook_wrap1()` 之前保存 `prepare_binprm` 目标地址和 BINPRM backend，使不确定安装结果仍可撤销。
- `kernelpatch_init()` 在调用 `kp_sucompat_hook_init()` 前先标记 rollback responsibility；即使 init 返回错误，也会执行清理。
- `kp_sucompat_hook_exit()` 改为返回错误状态，使用 `hook_unwrap_remove()` 的 checked API。
- 新增 `kp_unwrap_wait()`：遇到 `-EBUSY` 时 `cond_resched()` 并重试，直到 transit readers 排空；只有撤销成功或 `-ENOENT` 才清除目标地址和 backend 状态。
- init rollback 和 module_exit 对仍无法撤销的 sucompat hook 使用 fail-closed 处理，避免释放仍可能被执行的 LKM 代码。
- 同样将 getname_flags hook 的 teardown 改为 checked retirement。

### 测试与 CI 记录

相关代码提交：
- `cdcb31a77723add87f770c40f7fcbe84715192d7`：不确定安装前记录 prepare_binprm 目标；
- `7849a667a7170f2cd588815811d6a2cf77778b56`：teardown API 改为返回状态；
- `ddac2be42b3438826db38b7f100b1f10cb4f25fd`：init rollback / module_exit fail-closed；
- `d315bc0a895da713b1b2df94663a40ef4a2ed42f`：等待活动 transit readers 排空；
- `b7645988010d7e8623614998f7d8c422d9917246`：更新 LKM lifecycle source contract；
- `941cab5e72167c4bd15d29c12c20cf05c3f0887a`：增加 reader-drain source contract；
- `63ef0d82e8759e0567aa69ae72f1455123943a00`、`980bec8310860927aaf3469a607e1484e79579c0`：修复 API contract 测试脚本自身的 Python 语法与诊断字符串断言。

此前失败的 CI 均已定位为测试/契约问题，而非目标内核编译结果：
- 旧 lifecycle contract 仍要求 unchecked void teardown；
- API contract 测试曾误写 JavaScript `const`，造成 Python SyntaxError；
- SELinux diagnostic contract 曾把实际字符串 `selinux_blob_sizes hidden` 错写为 `kp_selinux_blob_sizes hidden`。

最新代码基线 `980bec8310860927aaf3469a607e1484e79579c0` 的 GCC 14.2 KPIMG 和 Windows workflow 当时仍在运行；不得提前记为成功。前置独立 LKM/KPM lifecycle contract 已通过。

### 验证边界

本轮证明的是源码生命周期修复和 Host/source contract 覆盖；尚未完成精确 Y73s vendor KDIR 编译、Clang 9.0.3 CFI/LTO + modpost、真实 `prepare_binprm.cfi` 机器码反汇编或真机执行。等待 reader drain 若 reader 永不退出会阻塞卸载，这是有意的安全取舍，避免带着仍活动的回调释放 LKM text。


## 40. 2026-11-10：SU cred 路径边界与跨任务提权 fail-closed

### 本轮 CI 复核

- 分支 1583204effafd41bd430ef31f95ad5871fddd035 的 GCC 14.2 Y73S KPIMG run 42811941593：success；KPIMG 构建和审计步骤全部通过。
- 同一提交 Windows workflow run 42811941751：最终 success；Ubuntu KPIMG / Linux kptools / source contracts 和 Windows kptools.exe 构建、打包均通过。
- 以上结果只覆盖 KPIMG、Host 工具和源码契约；不代表 Y73s vendor KDIR 下的 LKM .ko 编译/modpost 成功。

### 发现的 cred 风险

复核 accctl.c、su.c、dispatch.c 和 UAPI struct su_profile 后发现：

1. SUPERCALL_SU_TASK 对外可达并调用 kp_task_su()。旧实现用 prepare_creds() 复制调用者 cred，再直接写另一个 task 的 cred/real_cred，但没有按目标 task 的凭据上下文构造，也没有正确处理两个 cred 指针的引用计数与目标任务同步/生命周期。该路径不能安全启用。
2. su_profile.scontext 是固定长度 SUPERCALL_SCONTEXT_LEN 字段，用户传入结构体不保证 NUL 终止；旧 strlen(sctx) 可能越过字段边界。失败日志还可能打印未初始化的 sid。
3. su_cred() 原先未检查当前 user namespace 是否存在对应 UID/GID 映射。
4. kp_commit_su() 在 prepare_creds() 和 SELinux relabel 可能失败前就清除 _TIF_SECCOMP，失败时会留下不必要的 seccomp 状态变化。

### 修复

- kp_task_su() 现在明确返回 -EOPNOTSUPP，不再修改其他任务的 cred/real_cred；SUPERCALL_SU_TASK ABI 保留，但在实现安全的目标任务凭据复制、引用计数与同步前 fail-closed。
- SELinux context 长度改用 strnlen(sctx, SUPERCALL_SCONTEXT_LEN)，拒绝空串和未终止字段；sid 初始化为 0，错误日志不再打印未经终止保证的 context 字符串。
- su_cred() 先用 uid_valid() / gid_valid() 验证 namespace 映射，再写入凭据；无映射时返回 -EINVAL。
- seccomp 标志只在凭据准备与 relabel 成功后才清除。
- API contract 增加对应回归断言。

### 提交与新 CI

- 918a1b016f07e1e1d7506570d487668d366e3826：禁用不安全跨任务 cred 替换，并加固 SELinux context、UID/GID 映射和 seccomp 修改时序。
- 49911a64107b5d82769023de801b9af0be32d110：更新 accctl 接口说明。
- ee7c32b9f51548d74e4b53397f4f159ff92e3730：增加 Y73s 4.14 cred 安全契约断言。
- 最新 HEAD ee7c32b9f51548d74e4b53397f4f159ff92e3730 的 GCC KPIMG run 42812963481、Windows workflow run 42812963356 在本节写入时仍运行中；对应的后续 Windows workflow run 也有提交级独立触发。尚未把这些新提交标记为 CI 通过。

### 验证边界

本节的修复尚待新 CI 实际执行。仍缺精确 Y73s 4.14.141 vendor KDIR、生成头文件和匹配 Module.symvers，因此 .ko 编译、modpost、Clang 9.0.3 CFI/LTO 链接仍未验证；也没有真机加载或设备操作。跨任务 SU 目前是明确禁用，不应将其视为可用功能。


### 第 40 节 CI 验证结果补充（HEAD 5d1f3081）

- ee7c32b9 的第一次 GCC run 因旧测试夹具仍按 static void su_cred() 提取函数而失败；生产代码已改为 static int su_cred()，随后同步测试签名。
- 010cd59a 的第二次 GCC run 执行了新增边界用例，但旧断言仍假设 put_count 从 0 开始；新增的 unterminated-context fallback 用例已先释放一次 pending cred，故测试计数基准过时。已改为相对调用前计数断言。
- 最新代码/测试提交 5d1f3081c829da771db6e7b75d9411a0e83cd335 的 GCC 14.2 Y73S KPIMG run 42813617204：**success**。日志确认 4.14 API contract、unmapped UID/GID 拒绝、跨任务 SU fail-closed、seccomp 时序契约及后续全部 source contracts 通过。
- 同一提交的 Windows workflow run 42813617153：Ubuntu KPIMG、Linux kptools 和源码契约 job 已 success；Windows kptools.exe job 当时仍在运行，最终结果待确认。
- 本次测试夹具失败均已定位为旧断言/测试预期未同步，不是 KPIMG C 编译错误。仍未进行 Y73s vendor KDIR 下的 LKM 编译/modpost。


## 41. Y73s 原始 Boot 的 prepare_binprm / open_exec 入口反汇编核对（2026-11-10）

### 输入与完整性

- 从资料库读取原始 /boot.img：100,663,296 bytes，SHA-256 为 c47e94f64696fe70de11ea26cda4a3e0e6e025e581e7a96b95f1d975c9fe7cd5。
- Android Boot Header v2，page size 2048；gzip kernel payload 解压为 47,517,708 bytes。
- 解压 Kernel Image SHA-256：345bfab8217669cb84ed004916efea4fae06e6b169c70e1be2ec9ac3ad4f093e。
- 全程只读取资料库原件并在临时工作副本解压/反汇编，没有修改原件或接触设备。

### 目标符号和 CFI veneer

从同一份 Y73s KALLSYMS dump 确认：

- prepare_binprm.cfi：image offset 0x003e044c。
- prepare_binprm（非 .cfi 别名）：0x01917bc8，机器码为单条 B，目标 0x003e044c。
- open_exec.cfi：image offset 0x003e06e8。
- open_exec（非 .cfi 别名）：0x01914f00，机器码为单条 B，目标 0x003e06e8。

因此当前代码优先解析 prepare_binprm.cfi 会直接命中函数体；若退回 prepare_binprm 别名，hook() 的 branch_func_addr() 会把该 B veneer 解析到同一函数体。open_exec 别名同样是到 open_exec.cfi 的 CFI 跳板，作为函数指针调用入口。

### prepare_binprm.cfi 真实入口前四条指令

对原始 Kernel Image 的 0x003e044c 反汇编：

- 0x003e044c：0xd10143ff — sub sp, sp, #0x50
- 0x003e0450：0xa9015ff8 — stp x24, x23, [sp, #0x10]
- 0x003e0454：0xa90257f6 — stp x22, x21, [sp, #0x20]
- 0x003e0458：0xa9034ff4 — stp x20, x19, [sp, #0x30]
- 后续 0x003e045c：stp x29, x30, [sp, #0x40]。

当前 ARM64 hook 的 branch_absolute() 生成 4 条覆盖指令，因此入口补丁覆盖前 16 bytes，恰好是上述四条普通栈帧建立/寄存器保存指令；它们不含 PC-relative 地址或分支目标。hook_prepare() 对这些未命中 PC-relative relocation 分类的指令走 INST_IGNORE/relo_ignore，原样复制指令并填充 NOP，再跳回原函数 0x003e045c。就这份原始 Boot 的实际 prologue 而言，没有发现需要 ADR/ADRP、B/BL 或 literal LDR 重定位的入口指令。

### CI 补充

- 代码/测试 HEAD 5d1f3081c829da771db6e7b75d9411a0e83cd335 的 GCC 14.2 Y73S KPIMG run 42813617204：success。
- 同一提交 Windows workflow run 42813617153：最终 success；Ubuntu KPIMG/Linux kptools/source contracts 与 Windows kptools.exe 构建和 artifact 上传均成功。
- 状态文档后续提交不改变上述代码/测试基线。

### 验证边界

这是使用原始 Y73s Boot 的静态机器码与符号别名核对，不证明 hook 在运行时安装、回调 ABI 或卸载并发行为正确。目标 vendor KDIR 下的 LKM 编译/modpost、Clang 9.0.3 CFI/LTO 链接和真机运行仍未验证；没有刷写或设备操作。


## 42. KPIMG 原始 ELF metadata parser 测试接入与修正（2026-11-10）

### 变更

- 将 scripts/test_kpimg_setup_load_info.py 加入 .github/workflows/build-y73s-kpimg-gcc.yml，不再只是仓库中存在但未执行的测试。
- 测试从生产 kernel/patch/module/module.c 提取并执行 elf_header_check()、setup_load_info() 及其真实辅助函数，覆盖合法 ELF metadata 与畸形 section table、section-name table、文件 section 对齐、空 module name/version、SYMTAB/STRTAB 关系、符号名称偏移/终止符、符号 section index、RELA metadata。
- 第一次执行暴露的是测试夹具缺陷：elf_header_check() 不负责初始化 info->sechdrs，夹具却在调用 setup_load_info() 前解引用该指针。ASan 将故障定位到测试 main() 的空指针读取（地址 0x98），不是生产 parser 的执行路径。
- 修复夹具：畸形输入直接修改原始 ELF section-header table（image + SHOFF），并对合法 header check 的返回值作显式检查；保留 AddressSanitizer 运行以捕捉后续内存错误。

### 验证

- GCC 14.2 Y73S KPIMG run 42821643290，提交 0369d57f99ee88ef997f8dd6bd2bca25816d51db：success。
- 新增 KPIMG setup_load_info() 测试 16 项全部 PASS，且 AddressSanitizer 未报告错误。
- 同一工作流内原有 LKM setup_load_info() 测试、双 loader simplify_symbols() 测试、双 loader layout/final-copy 测试及 KPIMG metadata/RELA dispatcher 测试均通过。
- 同一提交 Windows kptools workflow 42821644835：success；Ubuntu KPIMG job 与 Windows kptools.exe build 均成功。

### 结论与边界

KPIMG metadata parser 的新增测试现已真实接入 CI，并在修复测试夹具后通过。该结果不替代 Y73s 4.14.141 vendor KDIR 下的 LKM 编译/modpost、Clang 9.0.3 CFI/LTO 链接或真机运行验证。


## 43. KPM 符号表重复布局与文件打开错误码修复（2026-11-10）

### 发现与修复

- 复核 KPIMG/LKM 两条 KPM loader 的 layout_sections() 与 layout_symtab() 时发现：恶意 ELF 若将 SHT_SYMTAB 或其关联 SHT_STRTAB 标记 SHF_ALLOC，前一阶段可能先分配，专用 symbol-table layout 又会再次分配并覆盖 section offset。
- LKM 与 KPIMG 的 setup_load_info() 现均拒绝 allocatable SYMTAB 和 allocatable symbol STRTAB，避免重复布局；分别补充真实 parser fixture 测试。
- load_module_path_event() / kp_load_module_path() 对 filp_open() 的 NULL 返回分支现明确返回 -ENOENT；原 PTR_ERR(NULL) 为 0，理论上可能错误报告成功。
- verify_kpm_loader_contract.py 增加两套路径加载器错误码契约和双 loader 的 SHF_ALLOC 防护检查。

### 验证

- GCC 14.2 Y73S KPIMG run 42823027868，代码/测试 HEAD 4cd248510e5f1a50fcc4cd557611e242a2d43030：success。
- LKM 与 KPIMG 两套 setup_load_info() 对 allocatable SYMTAB / STRTAB 的四项新增 fixture 检查全部 PASS。
- verify_kpm_loader_contract.py、双 loader simplify_symbols()、双 loader layout/final-copy、KPIMG metadata/RELA dispatcher、Y73S 4.14.141 API/source contract 均通过。
- Windows workflow run 42823027880：success；Ubuntu KPIMG 与 Windows kptools.exe 构建均成功。

### 验证边界

这些结果证明源码契约、Host fixture 与 KPIMG GCC 构建通过，不证明精确 vendor KDIR 下 LKM 编译/modpost、Clang 9.0.3 CFI/LTO 链接或 Y73s 真机加载/运行成功。


## 44. Loader 防护回归契约修正与最终 CI（2026-11-10）

- 第一次针对新增文件句柄错误码检查的 CI 在 verify_kpm_loader_contract.py 失败，原因是测试契约使用了错误的 LKM 函数名（实际为 kp_load_module_path）及过度转义的正则表达式；生产代码编译和 parser fixture 未出现对应失败。
- 已修正契约函数名与正则，重新执行最新分支代码/测试 HEAD 4cd248510e5f1a50fcc4cd557611e242a2d43030。
- GCC 14.2 Y73S KPIMG run 42823027868：success；verify_kpm_loader_contract.py、Y73S 4.14.141 API contract、LKM/KPIMG parser tests 均通过。
- Windows workflow run 42823027880：success，包含 Ubuntu KPIMG 与 Windows kptools.exe job。
- 状态文档本次提交之后的文档 HEAD 不改变以上代码/测试基线。


## 45. Y73s 4.14 无 init_mm 场景下 KPM NX 回收失败关闭（2026-11-10）

### 发现

- LKM KPM 的 kp_restore_nx_gp() 原先调用 set_memory_nx() 却忽略返回值；当 init_mm 不可解析且 module allocator/execmem 后端允许跳过 PTE walker 时，kp_update_bti_gp() 会按后端策略返回成功，可能掩盖 set_memory_nx() 的失败，随后 kp_free_exec() 将仍可能可执行的页面交还 allocator。
- Y73s 4.14 的 KALLSYMS profile 要求存在 set_memory_nx；但回收逻辑仍必须检查调用结果，不能只依赖符号存在。

### 修复

- kp_restore_nx_gp() 现在先调用 set_memory_nx() 并保存返回值。
- init_mm 不可用时，只有 set_memory_nx() 存在且返回成功，才允许 no-init_mm 快速路径完成；函数缺失或调用失败均返回错误，使 kp_free_exec() 按既有 fail-closed 策略泄漏该区域，而不是将可执行页交还通用 allocator。
- init_mm 可用时，仍允许 PTE walker 作为权威恢复/验证路径；即使 set_memory_nx() 报错，只要 PTE walker 成功更新并验证 NX/UXN/BTI 位，才允许释放。
- 删除 kp_unload_module() 中重复且未检查返回值的 set_memory_nx() 调用，统一由 kp_free_exec() 的 checked retirement 负责。
- 新增 scripts/test_kpm_execmem_restore.py，对缺失函数、NX 失败、NX 成功、init_mm PTE fallback 和恢复失败注入执行生产 helper。

### 验证

- GCC 14.2 Y73S KPIMG run 42824411097，代码/测试 HEAD 6311981f85030dad04de92a087bd4a29496c3fee：success；新增 NX restore fixture 五项全部 PASS。
- 同一提交 Windows workflow run 42824411048：success；Ubuntu job 中独立 LKM KPM loader contract、KPIMG build、Linux kptools/source contracts 均成功，Windows kptools.exe 构建及 artifacts 上传成功。

### 边界

该修复覆盖 no-init_mm 回收分支的失败关闭逻辑并由 Host failure-injection 验证；仍未在 Y73s 真机上实测 set_memory_nx 对 module_alloc 页面实际修改 PTE 的行为。目标 vendor KDIR 下 LKM 编译/modpost、Clang 9.0.3 CFI/LTO 链接和真机运行仍未完成。


## 46. Linux 4.14.141 set_memory_nx API 语义复核（2026-11-10）

- 对照 gregkh/linux v4.14.141 的 arch/arm64/mm/pageattr.c：set_memory_nx() 通过 change_memory_common() 更新 PTE_PXN，并返回 change_memory_common() 的错误码。
- change_memory_common() 会检查地址覆盖的 vm_struct、范围和 VM_ALLOC 标志；不满足条件时返回 -EINVAL，而不是保证成功。因此忽略返回值确实会把未成功设置 NX 的区域错误交还 allocator。
- 4.14 set_memory_nx() 为 EXPORT_SYMBOL_GPL；当前 Y73s KALLSYMS profile 要求 set_memory_nx 存在，运行时由 kallsyms_lookup_name 解析。此上游语义核对支持本次“无 init_mm 时必须检查 set_memory_nx 成功”的修复设计。
- 仍需 vendor 4.14.141 真实内核/KDIR 和设备运行才能确认厂商是否修改了 pageattr 实现，以及 module_alloc 返回区域是否满足 VM_ALLOC 覆盖条件；目前不将上游源码等同于 vendor runtime 证明。


## 47. 2026-11-10：SELinux translabel 失败时禁止替换为 init_cred

### 上游 4.14.141 布局核对

- 对照上游 `security/selinux/hooks.c` 与 `security/selinux/include/objsec.h`：4.14.141 的 `cred->security` 直接指向 `task_security_struct`，其前两个字段为 `osid`、`sid`；上游该版本没有 `selinux_blob_sizes`。
- 因此，只有在无 vendor blob-offset backport 且配置为单 SELinux LSM 时，`cred->security` 的 SELinux cred 偏移才可按 0 处理。若厂商内核引入了 blob-offset backport，则使用其 `lbs_cred`。
- 这项源码对照验证了 upstream 4.14.141 ABI，不等同于确认 Y73s vendor config 或 backport 状态；后者仍需目标 KDIR / 配置或运行时证据。

### 新发现与修复

- 原 `kp_apply_su_cred()` 在 SELinux context 转换失败时调用 `prepare_kernel_cred(NULL)`，用 `init_cred` 替换调用方持有的 pending cred。这会丢弃请求的 UID / SELinux 域，并可能将 kernel SID 的凭据带入用户态 exec 流程。
- 已删除该回退：SELinux translabel 不可用、context 无效或 SID 解析失败时直接返回错误；不替换 `*cred`，也不释放它。所有权仍归调用方，`kp_commit_su()` 会 abort 尚未提交的 cred；prepare_binprm 路径返回错误并让 exec 清理 pending cred。
- 更新 Host fixture：无效 context 现在必须得到 `-EINVAL`，且 pending cred 指针仍由调用方持有；移除原先“回退到 kernel cred”的测试预期。
- 更新 4.14 API source contract，禁止重新引入 `prepare_kernel_cred(NULL)` 回退。

### 验证边界

- 修复提交：`3c541adcfc08ed1ddd96657dfbba89df3d19d963`；Host fixture 更新：`7aa59ab140b5e01a5c2123b3b01094a1d9f8e36e`；source contract 更新：`d5d420d8c88ce96c6f3e54df3f7559a76ecf515f`。
- 4.14 GCC KPIMG 与 Windows workflows 已由最终 source-contract 提交触发，结果待完成；不得将前置中间提交或旧 CI 结果视为本次修复验证通过。
- 仍未完成 Y73s vendor KDIR 下的 LKM 编译/modpost、厂商 SELinux blob layout 验证或真机测试；没有进行设备刷写。


## 48. 2026-11-10：prepare_binprm 阶段不提前清除 seccomp

### Y73s 配置与 exec 顺序核对

- 从资料库中的 `vivo-y73s-4.14.141-extracted.config` 确认：`CONFIG_SECURITY_SELINUX=y`；SMACK、TOMOYO、APPARMOR 均未启用。该配置支持单 SELinux LSM 的 offset-0 fallback 前提，但不替代 vendor KDIR 的最终验证。
- 从原始 Y73s KALLSYMS 恢复记录确认存在 `install_exec_creds.cfi`（Image offset `0x003e0f6c`）。
- 对照上游 4.14.141 `fs/binfmt_elf.c`：`prepare_binprm()` 发生在 ELF 检查/加载前；`install_exec_creds()` 则在 `flush_old_exec()`、`setup_new_exec()` 之后，且其后 `setup_arg_pages()`、ELF segment mapping 等步骤仍可能失败。
- 因此，在 `kp_after_prepare_binprm()` 中清除当前任务的 `_TIF_SECCOMP` 太早：若后续 exec 在提交新 cred 前失败，原进程会带着已被清除的 seccomp 标志继续运行。

### 修复

- 删除 pending-exec callback 中提前清除 `_TIF_SECCOMP` 的操作；仅准备 `bprm->cred`，让内核在 `install_exec_creds()` 中按正常 exec 生命周期提交。
- 保留当前任务 seccomp 状态，即使后续 ELF 验证/加载失败也不会提前丢失限制。
- Host sucompat fixture 改为验证成功准备 pending root cred 后，`_TIF_SECCOMP` 仍保持设置；4.14 API contract 增加源码保护，防止该提前清除被重新引入。

### 仍需单独审计

- syscall-table backend 的 `kp_redirect_to_sh()` 目前在调用原始 `execve` 前执行 `kp_commit_su()`，随后仍有用户栈写入和原始 exec 失败的可能。Y73s 当前配置/符号分析指向隐藏 syscall table 后的 `prepare_binprm` fallback，但通用 syscall backend 的“先提交 cred、后完成 exec”事务仍需独立审计；本节没有声称已解决该 backend。
- 本节修复等待最新 GCC KPIMG / Windows workflow 验证；仍不是 vendor KDIR LKM build 或真机验证。

## 49. 2026-11-10：禁用非事务性 syscall SU backend，统一使用 pending exec cred

### 审计发现

- kp_redirect_to_sh() 原先在 syscall handler 内先执行 kp_commit_su()，立即替换当前任务凭据并清除 seccomp；之后才分配/写入用户栈中的新 filename、改写 argv，最后调用原始 execve()。
- 这些后续步骤均可能失败。若失败后走原始 execve passthrough，调用进程可能仍持有已提交的 root cred，却没有成功完成目标 shell exec。这是凭据提交顺序错误，不能仅靠把 kp_commit_su() 移到一次 copy_to_user() 之后修复，因为原始 execve 本身仍可失败。
- Y73s 当前静态符号/配置路径可用 prepare_binprm；此路径能修改 bprm->cred，由内核在 exec 正常提交阶段安装凭据。

### 修复

- 删除 kp_redirect_to_sh()、kp_execve_handler()、syscall-table execve hook 及其 getname_flags 路径探测辅助代码。
- kp_sucompat_hook_init() 现在只尝试 kp_hook_prepare_binprm()；不再回退到提前提交当前凭据的 syscall backend。
- 若目标内核无法解析/安装可靠的 prepare_binprm hook，初始化失败关闭，不提供 SU exec 提权路径。
- 保留 kp_after_prepare_binprm() 对 bprm->cred 的修改；在 prepare_binprm 之后、ELF 验证和 install_exec_creds() 之前，当前任务的 seccomp 状态保持不变。
- 修正 Host fixture 中因不再清除 seccomp 而变为未使用的 current_thread_info() stub。
- 更新 verify_lkm_supercall_input_contract.py 与 verify_y73s_414_api_contract.py：要求 sucompat 不得重新引入 kp_commit_su() / syscall hook / 用户栈早提交路径，且必须使用 pending exec credential backend。

### 验证

- 过程中发现并修复了两项过时测试契约：supercall input verifier 仍要求旧 kp_execve_handler()，4.14 API verifier 仍要求 syscall backend 使用的 current_user_stack_pointer() / strscpy()。这些是后端删除后的测试预期未同步，不是生产构建错误。
- GCC 14.2 Y73S KPIMG run 42830791161，HEAD 7acaa0ce78b853c07b5f263b5c96afccd787583c：**success**；KPIMG 构建、Host fixture、Y73S 4.14 API contract 与 source contracts 全部通过，artifact 上传成功。
- Windows workflow run 42830790621：**success**；Ubuntu KPIMG/source-contract job 与 Windows kptools.exe 构建均成功。
- 早期提交 e90594f3、8329f703 的 CI 失败分别由旧 source contract / 旧 API contract 引起；不能用这些中间提交的失败结果代替最终 HEAD 验证。

### 验证边界

本次只证明 GCC KPIMG 构建、Host fixture 和源码契约通过。没有 Y73s vendor KDIR，故未完成 LKM 对厂商内核头文件的真实编译/modpost；未完成 Clang 9.0.3 CFI/LTO 链接；也未在 Y73s 真机验证 hook 运行、SELinux 行为、exec 失败回滚或卸载并发。没有刷写或设备操作。

## 50. 2026-11-10：prepare_binprm 替换可执行文件时平衡 deny_write_access

### 发现与依据

- 对照 gregkh/linux v4.14.141 `fs/exec.c`：`do_open_execat()` 对打开的可执行文件调用 `deny_write_access(file)`；`open_exec()` 复用该路径；`free_bprm()` 对最终保留在 `bprm->file` 的文件调用 `allow_write_access()` 后再 `fput()`。
- `kp_before_prepare_binprm()` 原先将 `bprm->file` 替换为 `open_exec(KP_SH_PATH)` 返回的新文件，但旧文件只调用 `fput(old_file)`。这会遗漏旧文件对应的 deny-write 计数释放，可能使原 inode 保持写入受限。

### 修复

- 在替换前先调用 `allow_write_access(old_file)`，再 `fput(old_file)`；新 shell 文件保留在 `bprm->file`，后续由 Linux 4.14.141 `free_bprm()` 正常执行 `allow_write_access()` + `fput()`。
- Host sucompat fixture 加入 allow_write_access stub，并要求旧文件释放时该函数被调用。
- `verify_y73s_414_api_contract.py` 新增顺序契约：`allow_write_access(old_file)` 必须存在且先于 `fput(old_file)`。
- `sucompat_hook.h` 的旧 execve-hook 注释同步更正为 prepare_binprm pending-credential hook。

### 验证

- GCC 14.2 Y73S KPIMG run `42837667611`，代码/测试 HEAD `24a66bf3a642518291d7188ccd6feb4b786529d5`：**success**；sucompat Host fixture 与新增 deny-write 顺序契约均通过，Y73S 4.14.141 source contract 通过。
- Windows workflow run `42837667598`：Ubuntu KPIMG job 已 success；Windows kptools.exe job 在本节写入时仍运行中，最终结果待确认。

### 边界

该修复针对上游 Linux v4.14.141 的文件访问计数语义。Y73s vendor kernel 是否修改 `open_exec()` / `do_open_execat()` 仍需目标 KDIR 或厂商源码核对；当前没有 vendor KDIR，尚未完成 LKM 编译/modpost、Clang CFI/LTO 链接或真机验证。

## 51. 2026-11-10：prepare_binprm 的 filename/interp 所有权与重复调用审计

### 上游 4.14.141 源码核对

依据：
- `fs/exec.c`：`do_execveat_common()` 初始令 `bprm->interp = bprm->filename`；`free_bprm()` 仅在两者不相等时 `kfree(bprm->interp)`。
- `bprm_change_interp()` 同样只在旧 `interp` 与 `filename` 不相等时释放旧指针，然后为新解释器路径分配 `kstrdup()`。
- `fs/binfmt_script.c`：shebang 处理先释放旧 `bprm->file` 的 deny-write 引用和文件引用，再打开解释器、替换 `bprm->file`，并再次调用 `prepare_binprm()`。
- `do_open_execat()` 通过 `deny_write_access(file)` 建立可执行文件写入限制；`free_bprm()` 对最终文件执行 `allow_write_access()` + `fput()`。

上游源码：
- https://github.com/gregkh/linux/blob/v4.14.141/fs/exec.c
- https://github.com/gregkh/linux/blob/v4.14.141/fs/binfmt_script.c

### 对当前实现的结论

- 当前回调将 `bprm->filename` 和 `bprm->interp` 同时设为静态常量 `KP_SH_PATH`，两者保持指针相等。因此上游 `free_bprm()` 不会对静态常量执行 `kfree()`。
- 若后续 shebang 处理调用 `bprm_change_interp()`，上游逻辑看到旧 `interp == filename`，不会释放静态常量；随后将新解释器路径复制到堆上，最终由 `free_bprm()` 正常释放。
- `filename->name` / execveat 相对路径生成的 `pathbuf` 仍由 `do_execveat_common()` 外层分别通过 `putname(filename)` / `kfree(pathbuf)` 管理；本回调改写 bprm 字段不会转移这些外层对象的所有权。
- 已修复的旧文件 deny-write 平衡与脚本 binfmt 的释放顺序相容：当前 `bprm->file` 指向新 shell 文件；若它进入 shebang handler，handler 负责释放该文件，之后由解释器文件接管；普通 ELF 路径则由 `free_bprm()` 释放最终文件。
- `execveat` 使用相对 dirfd 或 `AT_EMPTY_PATH` 时，内核可能把 `bprm->filename` 规范成 `/dev/fd/<fd>/...` 或 `/dev/fd/<fd>`。当前基于路径字符串的 SU 匹配不会覆盖所有 fd-based execveat 形式；这是兼容性覆盖范围限制，不会把任意 fd 执行自动识别为 SU。

### 尚未关闭的条件性风险

- `prepare_binprm()` 并非在所有执行路径只调用一次：`binfmt_script` 在打开 shebang 解释器后会再次调用它。
- 当前回调的 before/after 局部标记只属于单次 hook invocation。若 `/system/bin/sh` 本身是 shebang 脚本，第二次 `prepare_binprm()` 会重新运行 `bprm_fill_uid()`，而当前实现不会把第一次调用的 SU 状态自动传递到第二次调用；pending euid/egid 可能被重置，导致预期的 SU exec 凭据不再可靠。
- Android 常见 shell 通常是 ELF/mksh，但本项目没有 Y73s 的 system 分区镜像或厂商源码可供本轮确认，不能把这一点当作已验证事实。必须从目标设备只读提取 `/system/bin/sh` 的文件类型/链接目标，或取得对应 system image 后确认它是 ELF，才能关闭该条件。
- 不建议在没有 per-`linux_binprm` 安全标记设计的情况下，简单地在第二次回调中按 `bprm->filename == KP_SH_PATH` 重新授予 root；这会把普通用户直接执行 shell 的路径混淆为先前的 SU 重定向。

### 本轮结论与验证边界

- 本轮没有发现 `filename/interp` 静态指针释放错误；没有修改生产代码。
- Windows workflow `42837667598` 的 Ubuntu KPIMG job 和 Windows kptools.exe job 均已 **success**。
- 仍需验证目标 `/system/bin/sh` 确为 ELF；仍缺 Y73s vendor KDIR、厂商 exec/LSM backport 源码、Clang CFI/LTO 链接和真机验证。没有执行刷写或设备操作。


## 52. 2026-11-10：脚本解释器链重复 prepare_binprm 的 SU 凭据失败关闭

### 上游调用链复核

- 对照 gregkh/linux v4.14.141 `fs/exec.c`：`prepare_binprm()` 每次调用都会执行 `bprm_fill_uid()`，该函数会先将 pending cred 的 euid/egid 重置为当前任务的有效 UID/GID；源码注释明确说明它可能因 script/binary chain 被多次调用。
- 对照 `fs/binfmt_script.c`：`load_script()` 释放旧执行文件、打开 shebang interpreter，并再次调用 `prepare_binprm()`。
- 对照 `security/selinux/hooks.c`：SELinux 的 `selinux_bprm_set_creds()` 在 `bprm->called_set_creds` 已置位时跳过重复 SID 转换。
- 对照 `security/commoncap.c`：commoncap 的 `cap_bprm_set_creds()` 会在重复调用时再次计算 capability；在 SU pending cred 与非 root 当前任务组合下，可能重算或降级 capability 集合。因此只恢复 euid/egid 不足以恢复完整 SU 凭据。
- `binfmt_misc` 在非 CREDENTIALS 模式也可能再次调用 `prepare_binprm()`；其 `bprm_change_interp()` 不替换 `bprm->filename`，所以静态 filename provenance marker 可覆盖这类解释器链。CREDENTIALS 模式是否重复 prepare 由其实际分支决定。

### 修复

- 使用独立的静态 `kp_sh_path[]` 对象作为唯一内部 provenance marker，避免比较两个字符串字面量指针的未定义/未指定行为。
- 首次 SU 重定向仍将 `bprm->filename` 和 `bprm->interp` 指向该静态对象。
- 后续 prepare hook 仅在 `bprm->filename == KP_SH_PATH` 时识别由本模块重定向的同一 exec 链；不按字符串相等把普通用户直接执行 shell 的请求误判为 SU。
- 检测到后续解释器 prepare 时返回 `-EOPNOTSUPP`，让 exec 失败并由内核清理 pending cred。暂不尝试只恢复 euid/egid，也不重复运行 SELinux profile 选择。
- 这是一项安全失败关闭措施，不是脚本 shell 兼容实现；如果 Y73s 的 `/system/bin/sh` 是 shebang 脚本，该 SU 路径将失败，直到实现并验证完整的多阶段凭据事务。

### 测试与 CI

- `scripts/test_y73s_414_sucompat_fallback.py` 模拟首次 SU redirect、`bprm_fill_uid()` 重置及第二次 prepare hook，要求第二次调用返回负错误码、不得再次应用 SELinux context，也不得把半准备凭据提交。
- `scripts/verify_y73s_414_api_contract.py` 增加源码契约，要求重复解释器链失败关闭。
- GCC 14.2 Y73S KPIMG run `42842463322`，HEAD `11f8c16b540e0ae95780dde14c1c78b053182377`：**success**；重复 prepare fixture、Y73S 4.14.141 API contract、源码契约与 KPIMG build 均通过。
- Windows workflow run `42842463706`：Ubuntu KPIMG job **success**；Windows kptools.exe job 在本节写入时仍运行中，待最终确认。
- 后续仅调整了注释和日志转义，未改变上述生产逻辑；最新分支 HEAD 以本节文档提交为准，仍需跟进该 HEAD 对应的 CI。

### 边界

- 该实现按 upstream v4.14.141 的 `bprm_fill_uid()`、script loader 与 commoncap 调用语义设计；Y73s vendor 是否 backport/修改这些路径仍需厂商源码或 KDIR 验证。
- 尚未取得目标 system image，无法确认 `/system/bin/sh` 的真实 ELF/shebang 类型。
- 仍未完成 vendor KDIR LKM 编译/modpost、Clang CFI/LTO 链接和真机执行验证。没有进行 Fastboot 或刷写操作。


## 53. 2026-11-10：确认 prepare_binprm hook 的 after 回调可覆盖原函数返回值

### Hook Engine 源码链路

本轮在仓库内找到并核对了实际 Hook Engine 实现，不再依赖对外部汇编实现的猜测：

- `kernel/include/hook.h` 将 `hook_fargs1_t` 定义为 `hook_fargs4_t` 的别名；该结构包含 `uint64_t ret` 字段。
- `hook_wrap1()` 明确调用 `hook_wrap(func, 1, before, after, udata)`。
- `kernel/base/hook.c:hook_chain_prepare()` 对 `argno <= 4` 选择 `_transit4`，并通过 transit stub 跳转到该 C 实现。
- `_transit4()` 先调用原函数并将其返回值写入 `fargs.ret`，随后逆序执行 after callbacks，最后执行 `return fargs.ret;`。
- 因而 `kp_after_prepare_binprm()` 对 `args->ret` 的修改会成为 `_transit4()` 的 C 返回值；按 AArch64 PCS，整数/指针标量返回值经 x0 交还给被 hook 的调用方。将负 errno 转成 `(unsigned long)(long)-EOPNOTSUPP` 也保留了 64 位负值表示，调用方按 int 返回值解释时低 32 位仍为负 errno。

### 结论

- **已从当前仓库实际源码确认：** `prepare_binprm` 的 `hook_wrap1` after callback 能覆盖原函数返回值；重复解释器链的 `-EOPNOTSUPP` 失败关闭路径并非只修改临时 callback 数据，而是会沿 Hook Engine 返回路径传回原调用者。
- 该结论适用于当前分支内编译的 `kernel/base/hook.c` Hook Engine。仍须确保最终 KPIMG 使用的正是该分支构建产物；不能把这一源码结论扩大为已完成 Y73s 真机运行验证。
- 已把上述链路加入 `scripts/verify_y73s_414_api_contract.py` 源码契约，防止后续误改 hook ABI、参数数量选择或 transit 返回语义。

### CI 与边界

- 最新分支 HEAD：`d7a350c2e9b48c91cf007b1cbef0dff229650139`。
- Windows workflow run `42842659767`：Ubuntu KPIMG build/source-contract job **success**；Windows kptools.exe job **success**。
- 本节新增的源码契约尚需在本次文档/测试提交后的新 CI run 中再次执行。
- 仍未取得 Y73s vendor KDIR/完整内核源码；LKM vendor KDIR 编译与 modpost、Clang CFI/LTO 链接、目标设备运行验证均未完成。没有执行 Fastboot、刷写或其他设备写入操作。


## 54. 2026-11-10：LKM Hook Engine transit 入口与模块卸载竞态审计

### 本轮确认

- `lkm/hook/hook_engine.c` 直接包含 `kernel/base/hook.c`，因此 `_transit4()` 等 transit C 函数位于 LKM 模块映像中，而不是位于独立保留的 chain payload 中。
- chain stub 将 chain 指针放入 x16，再经 x17 绝对跳转；transit 函数读取 x16。
- `_transit4()` 进入 LKM 函数后才增加 `active_readers`；callback owner pin 更晚才发生。
- `kp_sucompat_hook_exit()` 只在 `hook_unwrap_remove()` 返回 `-EBUSY` 时重试；观察到读者数为零后就可继续卸载。
- KPM owner registry 只对 KPM image 中的 callback 地址建立 owner ref；它不能自动 pin 当前 LKM 自身的 transit text。
- LKM `hook_mem_retire()` 仅移除链内存登记元数据，不释放 executable region；KPIMG arena 也不复用 retired slot。这能保护 chain payload 指针，但不能保护 LKM 中的 `_transit4()` 代码。

### 高优先级未关闭风险

存在一个尚未通过运行时复现、但从源码时序上成立的竞态窗口：CPU 可能已经从被 hook 的内核函数跳入 chain stub / LKM transit 路径，却尚未执行 `hook_chain_reader_enter()`。卸载线程此时可能看到 `active_readers == 0`，撤销 hook 并返回；如果随后 Linux module loader 释放 LKM 映像，前一个 CPU 仍可能继续执行已释放的 transit 代码。

当前 reader counter、KPM callback owner pin、保留 chain allocation 均不能单独证明关闭了这个 pre-reader 窗口。尚未证明为真实崩溃，但必须按高优先级生命周期风险处理。

### 需要满足的修复条件

- 生命周期屏障必须从 chain stub 第一条指令开始覆盖，直到 LKM transit 最终返回，包含 reader counter 尚未增加的区间。
- 必须证明屏障能抵御 CPU 抢占/中断，并在 Linux module loader 释放 LKM 映像前完成。
- 不能仅凭 `stop_machine()`、callback owner refs、`active_readers` 或保留 trampoline 内存就宣称安全。
- 需要确定性并发回归测试及目标内核验证。

### ABI / 构建检查

- `lkm/Kbuild` 为 `hook_engine.o` 关闭 CFI、LTO、stack protector，并在目标启用 SCS 时关闭 shadow-call-stack；源码契约现已检查这些保护选项。
- 新增源码契约也检查 x16/x17 stub 指令角色及 reader/pin/unpin 顺序。
- 本地 Clang AArch64 结构化探针观察到类似 transit 函数先保存常规寄存器，再捕获 x16；这不是 Y73s vendor KDIR 对象的实际反汇编，不能代替目标编译验证。

### 本轮结论

没有修改生产逻辑。**LKM 卸载安全尚未通过审计**，必须先解决 pre-reader transit lifetime window。仍缺 Y73s vendor KDIR、真实模块配置/对象反汇编和真机运行证据。


## 55. 2026-11-10：核实 Linux 4.14.141 module refcount 方案

- Y73s 原始 boot 配置已确认 `CONFIG_MODULES=y`、`CONFIG_MODULE_UNLOAD=y`。
- 精确上游 Linux `v4.14.141` 的 `module.h` / `module.c` 显示：模块 init 期间持有基础引用与临时引用；`try_module_get()` 在模块尚未进入 GOING 时可增加非零引用；普通 `delete_module` 会因额外引用而拒绝卸载。
- 因而在 init 成功返回前获取永久 self-reference，可以阻止普通 rmmod 进入 `kernelpatch_exit()`，作为“始终驻留”策略的安全遏制手段。
- 但这不是完整卸载修复：它会使正常卸载永久不可用；目前没有安全的 unpin 控制接口；boot 审计记录尚未确认 `CONFIG_MODULE_FORCE_UNLOAD`，强制卸载可能绕过引用计数。
- 不能在 `kernelpatch_exit()` 里才尝试 pin/unpin；该函数触发时机已经太晚。
- 长期方案应把 inline transit 放进 KPIMG 常驻文本或完全独立保留的可执行对象，并保证其全部调用依赖都不指向 LKM text。
- **本轮没有更改生产逻辑**，暂不启用永久 self-pin，避免在没有用户明确接受“不可普通卸载”的情况下改变模块管理行为。LKM transit 卸载安全仍未通过。
