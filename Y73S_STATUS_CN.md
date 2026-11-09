# Vivo Y73s 项目当前状态（唯一状态入口）

> 更新时间：2026-11-10  
> 当前分支：`y73s-cred-layout-guards-20261108`  
> 当前源码 HEAD（本次文档更新前）：`5ace9911f3996ddfe6866514f0989ef84c6955fd`  
> 本文是当前状态的权威摘要；历史审计报告保留技术证据，若历史记录与本文冲突，以最新源码和 CI 为准。

## 1. 当前结论

本轮完成了 KPIMG 启动映射、LKM/KPM ELF 与 ARM64 重定位、凭据偏移保护、任务扩展身份校验及 Kbuild 条件参数优化。

- 2026-11-09 代码基线的 Y73S GCC 14.2 KPIMG、Host kptools 和 Windows 构建曾通过。
- 2026-11-10 新增 Kallsyms/RELA/名称解析修改后，最新 HEAD 的 Actions 结果尚未取得；不能沿用旧 Run 作为最新通过证明。
- 目标 Linux 4.14.141 的真实 `.ko` 编译、KPM 动态加载、设备启动和 APatch/root 验证：尚未完成。

**因此当前结论是源码与 KPIMG 构建阶段取得进展，不是设备可用或可刷入版本。**

## 2. 分支与最近 CI（历史基线）

- 分支：[y73s-cred-layout-guards-20261108](https://github.com/ljx-91/kptools-fix/tree/y73s-cred-layout-guards-20261108)
- 本次文档更新前最近代码与契约提交：[5ace991](https://github.com/ljx-91/kptools-fix/commit/3f69f882ba5c5b4d98bcfb4976623b99dd3a1b69)

| 工作流 | Run | 结果 | 证明范围 |
|---|---:|---|---|
| Y73S Android KPIMG / GCC 14.2 | [42653184629](https://github.com/ljx-91/kptools-fix/actions/runs/42653184629) | 成功 | Y73S KPIMG 构建、栈帧与映射审计、打包 |
| Y73S host kptools + source contracts | [42653184913](https://github.com/ljx-91/kptools-fix/actions/runs/42653184913) | 成功 | Host 工具构建、12 项源码契约验证 |
| KernelPatch Windows Build | [42653184632](https://github.com/ljx-91/kptools-fix/actions/runs/42653184632) | 成功 | Android KPIMG 与 Windows kptools.exe 构建及打包 |

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
