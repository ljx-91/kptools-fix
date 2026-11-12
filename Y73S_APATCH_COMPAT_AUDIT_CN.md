# vivo Y73s APatch / KernelPatch 4.14.141+ 兼容性审计

日期：2026-11-12  
仓库：ljx-91/kptools-fix  
分支：y73s-cred-layout-guards-20261108  
本轮最新源码/测试基线：79e567c1a24f7e93a7c1665b17a4a3be3b2c60d4（后续仅文档更新）

## 1. 范围与结论

本轮将上游 KernelPatch #189 的 Y73s 故障记录与本分支的真实原厂 Boot、符号解析器、SELinux AVC Hook 进行交叉核验。只做源码修改、Host/Android 构建、离线镜像处理和静态校验；没有连接设备、Fastboot、Recovery、分区写入或真机启动。

结论：本分支已增加一个严格限定于 Y73s V2031A / PD2031、ARM64、Linux 4.14.141、原始 Image 长度 47,517,708 bytes 的 `avc_denied` 静态函数指纹回退。它解决的是该内核将静态 `avc_denied` 从 KALLSYMS 隐去的问题；它不等于已经证明 APatch Manager 鉴权、Root 授权、KPM 动态加载、Wi-Fi 稳定性或设备启动全部正常。

## 2. 原厂镜像与函数指纹的独立验证

原厂 Boot：
- 大小：100,663,296 bytes
- SHA-256：`c47e94f64696fe70de11ea26cda4a3e0e6e025e581e7a96b95f1d975c9fe7cd5`

从该 Boot 的 gzip kernel 解压得到：
- Image 大小：47,517,708 bytes
- SHA-256：`345bfab8217669cb84ed004916efea4fae06e6b169c70e1be2ec9ac3ad4f093e`

针对历史补丁中记录的 Y73s `avc_denied` 候选：
- 函数入口 Image offset：`0x0069141c`
- 完整入口指纹：31 条 ARM64 指令，逐字匹配。
- 调用点 Image offset：`0x00691d74`
- 调用点指令：`0x97fffdaa`（BL）
- 对该 BL 解码后的目标：`0x0069141c`，与候选函数入口完全一致。

这比只按固定 offset 写入更严格：代码同时要求 ARM64、Linux 4.14.141、little-endian、原始 Image 长度完全匹配、31 条入口指令匹配，并要求调用点 BL 实际指向该入口。任一条件不满足即不采用该回退。

## 3. 本轮源码修改

### `tools/symbol.c`
- 新增 `resolve_y73s_avc_denied_fingerprint()`。
- 首先尝试普通 KALLSYMS 名称解析；仅在名称不存在时，才尝试 Y73s 专用指纹。
- 指纹校验失败时返回 0，不猜测地址、不继续使用未经验证的候选。

### `tools/patch.c`
- 原先调用 `fillin_patch_config(..., kinfo->is_be, 0)`，将 Android 标志硬编码为 false。
- 已改为传入实际 KPIMG 配置中的 `is_android`。
- 这样 Android 镜像在普通符号解析和 Y73s 专用指纹都失败时，会触发原有 fail-closed 检查，而不是静默跳过 `avc_denied` 要求。

### `scripts/verify_y73s_avc_denied_fallback.py`
- 校验 C 源码中的 31 条指纹与已独立验证的指令序列一致。
- 校验 ARM64 / 4.14.141 / Image 长度 / little-endian 限制。
- 校验调用点必须是 BL，且目标必须等于函数入口。
- 校验 Android 标志确实传入 patch-config 检查。
- 校验 `avc_denied` 是 SELinux 决策 Hook，`slow_avc_audit` 仅是次级审计路径。
- 可选传入原始 kernel.Image 文件，对完整 Image SHA-256、函数指令和调用点执行验证。
- 已接入 `.github/workflows/build-y73s-kptools-host.yml`。

## 4. SELinux AVC 兼容性判断

Y73s 符号审计结果：
- `avc_denied`：不在导出的 KALLSYMS 中。
- `slow_avc_audit`：存在，Image offset `0x01917b34`。
- 历史 Y73s 函数指纹定位的 `avc_denied`：`0x0069141c`。

当前 `kernel/patch/common/accctl.c` 的行为是先 Hook `patch_config->avc_denied`，成功后返回；只有主 Hook 不可用时才尝试 `slow_avc_audit`。后者不能代替修改 AVC 决策结果的主 Hook，不能仅凭审计 Hook 成功就宣称 SELinux 权限决策已绕过。

替换函数保留了 Y73s 旧内核的 8 个寄存器参数布局兼容分支：当旧 ABI 的首参数表现为 32 位值时，从 `_flags` 取 `av_decision` 指针。该分支已被源码契约检查，但实际设备调用 ABI 仍需运行时验证。

## 5. 实际离线修补验证

使用本分支构建产物对原厂 Boot 副本执行 `kptools -p`：
- Host kptools 版本：`d0a`
- KPIMG 版本：`d0a`
- 原厂 Boot 输入 SHA-256：`c47e94f64696fe70de11ea26cda4a3e0e6e025e581e7a96b95f1d975c9fe7cd5`
- 工具日志明确输出：`vivo Y73s 4.14.141 avc_denied fingerprint verified: 0x0069141c`
- `slow_avc_audit` 解析到 `0x01917b34`
- `rest_init` 解析到 `0x018f1280`
- `kernel_init` 虽未导出，但从 `rest_init` 的 `kernel_thread` 调用点恢复到 `0x018f1354`
- `__cfi_slowpath` 解析到 `0x002ddc00`；`report_cfi_failure` 与 `__cfi_slowpath_diag` 仍不存在。
- 自动 repack 成功；再次 unpack 成功；对解包后的 kernel 执行 `kptools -d` 成功，输出 108,006 条符号记录，关键符号偏移与原始基线一致。

离线测试输出：
- 文件：`y73s-avc-fallback-audit-only.img`
- 大小：100,663,296 bytes
- SHA-256：`c13992164c1b906d63c38db5888cc1fe543ea85f3cfe52eba7c0b10eafd726d3`

**AVB 状态：未通过原厂 Boot Hash Descriptor。** 按原厂 salt 和 17,618,944-byte descriptor 范围计算，测试输出摘要为 `8af33870c5e108c134750ced150cffc39fdf4a94b204500081eab99c18599925`，与原厂摘要 `36a3d398fc5a5350e1642f54584ebca8d06e20644e622993f9547e057467623c` 不同。kptools 也明确提示保留 AVB 元数据不等于重新计算分区摘要或签名。该文件只用于离线验证，不是已验证可刷写镜像。

## 6. CI

- Linux Host kptools + 仓库源码契约：Run [43072740995](https://github.com/ljx-91/kptools-fix/actions/runs/43072740995)，成功；AVC 指纹和 CFI slowpath profile 检查全部 PASS。
- Y73s GCC 14.2 Android KPIMG：Run [43072740986](https://github.com/ljx-91/kptools-fix/actions/runs/43072740986)，成功。
- Windows kptools：Run [43072741042](https://github.com/ljx-91/kptools-fix/actions/runs/43072741042)，成功；Windows kptools.exe 构建、DLL 收集、Smoke Test、ZIP 打包和上传全部通过。

## 7. 仍未解决

1. 未在目标设备验证 APatch Manager SuperKey 鉴权、Root 授权、KPM load/unload。
2. 上游 KernelPatch #189 报告的 Wi-Fi 连接后崩溃及 Vivo 安全模块交互问题，不能由符号修复推断已经解决。
3. Y73s CFI 仅找到 `__cfi_slowpath`；KPIMG / LKM 的 Hook 所有权与实际加载组合仍需单独验证。
4. `kernel_init` 的静态恢复和 PRE/POST_KERNEL_INIT Hook 尚无设备日志闭环。
5. 仍缺少与原厂 4.14.141+ 完全匹配的 vendor KDIR、生成头文件和 `Module.symvers`，不能声称目标 .ko 已完成 Kbuild/MODPOST。
6. AVB 签名/摘要处理仍未解决；不进行刷写或真机启动。

## 8. 上游参考

- KernelPatch Y73s issue #189：https://github.com/bmax121/KernelPatch/issues/189
- PR #208：https://github.com/bmax121/KernelPatch/pull/208
- PR #225：https://github.com/bmax121/KernelPatch/pull/225

上游 issue 评论中，设备报告者指出旧工具对该内核的函数地址识别错误，并建议使用 #208 的严格符号定位思路、回退 #225；原作者随后强调正确符号位置只是第一步，Vivo 安全模块仍可能引入其他问题。本分支不直接复制上游的盲目固定地址，而是对目标原厂 Image 做版本、长度、指令和调用目标的多重校验。


## 9. Y73s CFI slowpath Hook 的静态兼容性复核

对同一份原厂 kernel.Image（SHA-256 `345bfab8217669cb84ed004916efea4fae06e6b169c70e1be2ec9ac3ad4f093e`）进一步检查：
- `__cfi_slowpath` Image offset：`0x002ddc00`；`report_cfi_failure` 与 `__cfi_slowpath_diag` 均不存在。
- 函数入口前四条指令：`0xd10103ff`、`0xa90157f6`、`0xa9024ff4`、`0xa9037bfd`，是普通栈帧/寄存器保存指令，没有 PC-relative branch、ADR/ADRP 或 literal load。
- KPIMG 的 `branch_absolute()` 覆盖四条指令；`hook_prepare()` 对覆盖指令逐条执行 relocation；上述普通指令走 `INST_IGNORE -> relo_ignore()` 原样复制路径，因此静态上可安全搬迁这 16-byte prologue。
- 函数体在 offset `+0x1c` 出现 `0xaa0203f4`（使用 X2），确认该目标实现确实消费第三个参数；KPIMG 的 `replace__cfi_slowpath(uint64_t id, void *ptr, void *diag)` 与备份函数指针保持三参数 ABI。
- 新增 `scripts/verify_y73s_cfi_slowpath_profile.py` 并接入 Host CI；可选传入原始 Image，验证 Image SHA、函数入口指令和 X2 参数使用。
- 源码契约日志：Run [43072740995](https://github.com/ljx-91/kptools-fix/actions/runs/43072740995) 的 Audit LKM KPM ELF loader source job 成功，CFI profile 检查全部 PASS。

**边界：**这证明当前目标函数入口适合现有四指令 trampoline，且替换函数参数数目匹配；不证明目标设备上的 hotpatch 写入、缓存同步、并发调用、KPM CFI 旁路或 Wi-Fi 连接后的稳定性。仍需设备运行日志才能关闭上游 #189 的运行时故障。


## 10. LKM Manager 身份与 KPM 管理权限隔离复核

### 发现

对照 KPIMG 的 `kernel/patch/common/supercall.c` 与 standalone LKM 的 `lkm/supercall/supercall.c`，发现 LKM 旧入口只判断“trusted manager UID 或 SU allowlist UID”，随后把所有命令交给同一个 dispatcher。这样普通已获 SU 授权的应用也可能调用 KPM_LOAD / UNLOAD / CONTROL / NUMS / LIST / INFO；这不符合 KPIMG 的 `is_authed` 管理权限边界。

### 已修复

- 新增 `kp_supercall_manager_only()`，明确把六个 KPM 管理命令限定为可信 Manager UID。
- pt_regs syscall backend 与 Y73s Linux 4.14 六寄存器 legacy backend 均在 dispatcher 前执行同一权限检查；普通 SU allowlist 用户对 KPM 管理命令收到 `-EPERM`。
- 未授权 UID 仍原样调用原始 `truncate`，不改变普通系统调用行为。
- 将 Manager APK / packages.list 同步扫描及 packages.list rename refresh hook 移到 syscall 45 发布之前，避免 supercall 已可调用而 manager UID 尚未初始化的窗口。
- init 失败路径显式移除 manager refresh hook，避免模块释放后残留回调。
- 新增 `scripts/verify_lkm_manager_auth_contract.py`；更新 `scripts/test_y73s_414_supercall_abi.py`，直接编译执行真实 legacy handler 片段，覆盖：普通未授权 passthrough、普通 Manager 命令、SU allowlist 用户被拒绝 KPM、trusted manager 成功调用 KPM、缺失 trampoline fail-closed。

### 验证

- Linux Host + 仓库源码契约：Run [43077994524](https://github.com/ljx-91/kptools-fix/actions/runs/43077994524)，成功；manager-auth contract 全部 PASS。
- Y73s GCC 14.2 KPIMG：Run [43077994724](https://github.com/ljx-91/kptools-fix/actions/runs/43077994724)，成功；4.14 ABI fixture 明确输出 SU allowlisted non-manager denied KPM、trusted manager KPM dispatch 两项 PASS。
- Windows kptools / Android KPIMG workflow：Run [43077994511](https://github.com/ljx-91/kptools-fix/actions/runs/43077994511)，整条 workflow 成功；Android KPIMG、Linux kptools、源码契约、Windows kptools.exe、DLL 收集、Smoke Test、ZIP 与 Artifact 上传全部通过。

### 与 APatch SuperKey 问题的关系及限制

这次修复的是 LKM 的 Manager UID / KPM 管理权限边界，不等于已经解决上游 #189 的 APatch Manager “Authentication Failed”。LKM dispatcher 目前没有实现 `SUPERCALL_SKEY_GET` / `SUPERCALL_SKEY_SET` / `SUPERCALL_SKEY_ROOT_ENABLE`；KPIMG 路径才保留上游 SuperKey 认证分支。Manager APK 证书信任和 SuperKey 认证是两条不同路径，不能混为一谈。

此外，本轮 CI 没有目标 PD2031 4.14.141+ vendor KDIR，因此没有编译/MODPOST 出真实 Y73s LKM .ko；也没有设备端 manager UID 扫描日志、SuperKey syscall trace、KPM load/unload 运行记录。不能据此宣称真机鉴权或 Root 已经工作。


本轮源码/测试 CI 提交：`d39cbe92d463ca6a1fb0b2f16affcfad64426b6d`；本轮后续提交仅更新审计文档。


## 11. Root SuperKey 校验路径与内存边界修复

### 核对结果

针对原始故障日志中的 `-S testtest123`，重新计算 SHA-256 得到：

`626aa60100e38a2b0a8c9b3512116bfb3ff9db5b986b21b27c2989e011629435`

与原厂 kptools 日志中的 root-superkey verifier 完全一致。故障日志中的哈希本身没有计算错误。

### 源码问题与修复

旧 `auth_superkey()` 按 preset 随机 SuperKey 的长度读取输入 key，却没有先比较输入长度或停止在输入 NUL 处；Root-key 模式下，用户输入可能比随机 preset key 短，旧代码会读取 NUL 后未初始化的栈数据。虽然 Root hash fallback 随后可能成功，但前置比较存在未定义读取，不能保留。

已修改 `kernel/base/predata.c`：
- 先拒绝 NULL、无 NUL 终止或长度达到 `SUPER_KEY_LEN` 的输入。
- 先比较输入长度与 preset key 长度，再只读取双方有效字符，消除越过 NUL 的读取。
- Root hash fallback 只有在 `enable_root_key`、`root_superkey_is_set` 和 verifier 指针均有效时才执行。
- SHA-256 仅处理已验证的 `key_len` 字节。
- Root hash 首次验证成功后仍按既有逻辑迁移为 active SuperKey 并关闭 root-key fallback。

### 执行测试

新增 `scripts/verify_y73s_superkey_contract.py`，核验 kptools `-S` 写入哈希与内核读取/验证路径一致；新增 `scripts/test_y73s_root_superkey_auth.py`，抽取真实 `auth_superkey()` 并链接真实 `kernel/base/sha256.c`，在 Host C 编译器执行：
- `testtest123` 对应已知 root hash 验证成功并迁移。
- 迁移后精确密钥成功、错误密钥失败。
- NULL 和无终止符输入失败关闭。
- 普通 embedded SuperKey 要求长度和内容都完全匹配。

CI：
- Linux Host + 真实 C 运行测试：Run [43079653529](https://github.com/ljx-91/kptools-fix/actions/runs/43079653529)，成功；Root SuperKey 认证、迁移、错误 key 和异常输入测试全部 PASS。
- Y73s GCC 14.2 KPIMG：Run [43079653564](https://github.com/ljx-91/kptools-fix/actions/runs/43079653564)，成功；相同真实 C 测试在 KPIMG 构建流水线执行通过。
- Windows + Android KPIMG：Run [43079653598](https://github.com/ljx-91/kptools-fix/actions/runs/43079653598)，Android KPIMG / Linux Host job 成功；Windows kptools.exe job 在本报告更新时仍在执行。

**限制：**该测试证明 Root SuperKey verifier 的真实 C 函数与 SHA-256 在 Host 环境下符合预期；不证明 Y73s 设备上的 syscall 45 Hook 一定收到 Manager 传入的正确 x0 指针，也不证明 Manager UID 检测、SELinux 域、Supercall 命令传递或 Root 授权完整链路已正常。仍需设备日志闭环。


本轮 SuperKey / Manager 权限相关源码与测试提交：`a92d0fd21568248c0ab339cbded1b3539fe015d4`；其后提交仅更新 CI 文档。


## 12. KPIMG Supercall Manager 早期授权路径修复

进一步审计发现，KPIMG `before()` 在确认 Manager 身份之前先执行 `get_ap_mod_exclude(uid)`，并且在复制 x0 key 字符串失败时直接 return。两条早退路径都会阻断后续可信 Manager UID 的 `is_authed = 1` 分支：如果 Manager UID 被误加入 per-app exclude，或其 key 参数复制暂时失败，可信 Manager 也无法使用 syscall 45。

已调整顺序：
- 先识别 `is_trusted_manager_uid(uid)`。
- per-app exclude 仅拦截非 Manager；可信 Manager 保留管理通道。
- SuperKey 复制失败时，非 Manager 仍 fail closed；可信 Manager 继续进入既有 Manager 授权分支。
- 若 key 可复制，仍正常调用 `auth_superkey()`，保留 Root SuperKey 首次验证和迁移逻辑。

另外新增 `scripts/test_y73s_supercall_arg_capture.py`，提取真实 `syscall_args()` / `syscall_argn()` 并按 `hook_fargs8_t` 的真实前缀布局（chain、skip_origin、local、ret、args）编译执行；断言 `hook_fargs6_t` 与该布局兼容，并分别验证 Y73s 4.14 无 wrapper inline 路径及 pt_regs wrapper 路径的 x0-x5。

验证：
- Linux Host / 源码契约 Run [43080710934](https://github.com/ljx-91/kptools-fix/actions/runs/43080710934)，成功；Manager exclude/key-copy 早期授权检查、真实 SuperKey C fixture、真实 syscall x0-x5 capture fixture 全部 PASS。
- Y73s GCC 14.2 KPIMG Run [43080712484](https://github.com/ljx-91/kptools-fix/actions/runs/43080712484)，成功；KPIMG 交叉编译和全套回归测试通过。
- Windows + Android KPIMG Run [43080711483](https://github.com/ljx-91/kptools-fix/actions/runs/43080711483) 整条 workflow 成功；Android KPIMG、Linux kptools、源码契约、Windows kptools.exe、DLL 收集、Smoke Test、ZIP 与 Artifact 上传全部通过。

**边界：**以上仍是离线 C fixture、源码契约和交叉编译，不是目标设备上的 syscall 45 trace。要最终确认 Authentication Failed 是否消失，仍需真实 Manager UID、x0 指针、key-copy 返回值、`auth_superkey` 返回值、命令号和 `args->ret` 的设备日志。


本轮 Manager / SuperKey / syscall 参数链路源码与测试提交：`d58fc4220fee22ba8ea49ead66a9ee17ad98c119`；其后提交仅更新审计文档。


## 13. 2026-11-12：SuperKey 设置命令的用户态指针二次解引用修复

### 发现

继续审计 KPIMG `kernel/patch/common/supercall.c::call_skey_set()` 时发现：旧实现虽然先用 `compat_strncpy_from_user()` 将 key 复制到内核栈缓冲区，却在最后仍将原始用户态指针 `new_key` 传给 `reset_superkey()`。这使先前的有界复制并没有成为实际写入的数据源；如果用户映射在复制后变化或失效，内核仍会再次解引用用户指针。此外，旧实现没有可靠地拒绝负错误码和空 key。

### 已修复

- 复制失败时返回原始负错误码，不修改当前 SuperKey。
- 拒绝空 key（`-EINVAL`）。
- 拒绝长度达到缓冲区容量、无法证明 NUL 终止的输入（`-E2BIG`）。
- 只将内核栈缓冲区 `buf` 传给 `reset_superkey()`，不再二次读取用户指针。
- 长度比较显式转换为 `int`，避免 Host 严格编译下 signed/unsigned 比较警告。

### 回归测试

- 更新 `scripts/verify_y73s_superkey_contract.py`，固定上述错误处理和“只提交内核副本”契约。
- 新增 `scripts/test_y73s_skey_set_input.py`，抽取仓库真实 `call_skey_set()`，在 Host C 编译器下测试正常 key、用户复制错误、空 key、无终止符超长 key；同时确认 `reset_superkey()` 收到的不是原始用户指针。
- 已将新测试加入 Linux Host 和 Y73s GCC 14.2 KPIMG 两条 CI workflow。
- 对等价 C fixture 使用 `-std=gnu11 -Wall -Wextra -Werror` 编译执行，四类边界用例通过。GitHub Actions 对最新分支提交的运行结果尚未取得，因此不提前标记 CI 通过。

源码/测试提交序列：
- `618376b50c2aed47583583793788c0aa06f99077`：修复用户态指针二次解引用和输入边界。
- `64bde1c916629c6489e8bd40e33895b122c06682`：增加源码契约断言。
- `124b25d11c42cf11d1e67229b6c2b2152a3c2304`：新增运行时 C fixture。
- `65c0e68d386ed7c6feea3a0e62200e154f10fdd6`、`78d9d572c466f012388a15d3ef2bd416df41f502`：将测试接入 Host / KPIMG CI。
- `bc0d646993e2ad6ad3349c3feab615088018d02a`、`7ca03f3ea638a77d6145258a12fa8827ec58f0ed`、`79e567c1a24f7e93a7c1665b17a4a3be3b2c60d4`：修正严格编译下的长度比较及负向指针 fixture 类型。

### 限制

该修复只闭合 KPIMG SuperKey 设置命令的用户态输入边界；不等于真机 Manager 鉴权、Root 授权、KPM 管理或 AVB 已通过。AVB Hash Descriptor 仍不匹配；没有目标设备运行日志，也没有执行刷写。


## 97. 2026-11-12：Manager UID refresh 并发发布与读取同步

### 发现与修复

前一轮将 Manager UID refresh 改为 spinlock + generation 后，继续审计发现旧 UID 的撤销/发布已受锁保护，但导出的 is_trusted_manager_uid_android() 与 get_trusted_manager_uid() 仍直接读取全局 UID，和 refresh 写入之间存在未同步的数据竞争。

已完成：
- is_trusted_manager_uid_android() 和 get_trusted_manager_uid() 现在都在 trusted_manager_refresh_lock 下读取 UID，与刷新路径使用同一把锁。
- refresh 在扫描前先增加 generation 并撤销旧 UID；APK / packages.list 文件 I/O 不在 spinlock 临界区内执行。
- 扫描完成后重新加锁；若 generation 已变化，返回 -EAGAIN，不允许旧扫描覆盖较新的刷新结果。
- 扫描失败保持 UID invalid；只有完整扫描成功才发布新 UID。
- 按本仓库 KernelPatch 定制接口修正调用方式：spin_lock_irqsave(lock) 返回 flags，不能使用上游常见的双参数形式。KPIMG 交叉编译已验证该接口。

### 回归测试与 CI

- 更新 scripts/test_y73s_manager_uid_refresh.py：从真实源码抽取 refresh、UID reader 和 getter 函数，编译并执行；覆盖成功替换 UID、扫描失败撤销旧 UID、扫描被更新 generation 抢占时返回 -EAGAIN 且不发布 UID，以及两个读路径的锁行为。
- 更新 scripts/verify_y73s_superkey_contract.py：检查 IRQ-safe spinlock、generation 防旧扫描发布、失败 fail-closed，以及导出读路径锁保护。
- Linux Host / kptools / 源码契约：Run [43217973860](https://github.com/ljx-91/kptools-fix/actions/runs/43217973860)，成功；Audit job 输出 Manager UID spinlock、读路径同步契约 PASS。
- Y73s GCC 14.2 KPIMG + Windows kptools：Run [43217973657](https://github.com/ljx-91/kptools-fix/actions/runs/43217973657)，整条 workflow 成功；Android KPIMG 交叉编译成功；Windows kptools.exe 构建、DLL 收集、Smoke Test、ZIP/checksum 打包及 Artifact 上传全部通过。
- Host runtime fixture 输出：[PASS] superseded scan cannot publish stale UID、[PASS] runtime trusted Manager UID refresh fixture。

### 仍需验证

这些结果证明当前分支在 Host fixture、源码契约、Y73s GCC 14.2 KPIMG 交叉编译和 Windows kptools 工作流中通过；不证明设备运行时 APK 安装/卸载与 packages.list rename 竞争场景全部覆盖，也不证明真机 Manager 身份、SuperKey、Root 或 KPM 操作已成功。仍需检查调用时机和设备日志闭环。

**当前分支提交：** dd891c17c863033bd0f9f3ea09aa6a9baedeb0db。


## 14. 2026-11-12：Trusted Manager UID 刷新竞态与读取同步

### 风险与修复

审计发现，Manager UID 刷新失败时若保留旧 UID，会让已经卸载或替换的 Manager UID 继续拥有可信身份；并发扫描还可能出现较早启动的扫描晚完成、覆盖较新扫描结果的竞态。

当前实现已调整为：

- 使用仓库自带的 spinlock.h 单参数 spin_lock_irqsave(lock) API；保存返回的 IRQ flags，并在所有路径配对 spin_unlock_irqrestore()。
- 进入刷新时先在锁内递增 trusted_manager_refresh_generation 并撤销旧 UID；锁外完成 APK 证书和 packages.list I/O，避免在 spinlock 临界区内执行可能阻塞的文件操作。
- 扫描结束重新加锁；generation 已变化则返回 -EAGAIN，不发布旧扫描结果；失败时继续保持 UID invalid，只有当前 generation 的成功扫描才能发布 UID。
- is_trusted_manager_uid_android() 和 get_trusted_manager_uid() 均在同一 spinlock 下读取 UID 快照，避免读写并发数据竞争。

### 回归测试与 CI

- 更新 scripts/verify_y73s_superkey_contract.py，检查仓库真实单参数 spinlock API、generation stale-scan 拒绝逻辑、刷新前撤销旧 UID，以及所有导出 UID 读取路径的同步。
- 更新 scripts/test_y73s_manager_uid_refresh.py，抽取真实刷新函数并编译执行，覆盖成功替换 UID、失败刷新撤销 UID、被新一轮刷新抢占时旧扫描返回 -EAGAIN 且不发布，以及锁正确释放。
- Y73s GCC 14.2 KPIMG Run [43217973570](https://github.com/ljx-91/kptools-fix/actions/runs/43217973570)：成功；源码契约、Manager UID runtime fixture、SuperKey runtime fixture 和 KPIMG 交叉编译均通过。
- Linux Host Run [43217973860](https://github.com/ljx-91/kptools-fix/actions/runs/43217973860)：成功；Host kptools 构建与仓库源码审计通过。
- Windows Build Run [43217973657](https://github.com/ljx-91/kptools-fix/actions/runs/43217973657)：成功；Android KPIMG/Linux kptools 阶段、Windows kptools.exe 构建、打包与 Smoke Test 均通过。

当前验证基线：dd891c17c863033bd0f9f3ea09aa6a9baedeb0db。

### 限制

这些结果证明源码契约、Host runtime fixture 和构建流程通过，不等于 Y73s 真机 Manager UID 更新时序已验证。仍需设备侧确认 packages.list 替换时机、APK 证书校验、并发刷新日志和 APatch Manager syscall 45 鉴权结果。AVB Hash Descriptor 仍未匹配，当前修补 boot 仍不可刷写；目标 4.14.141+ vendor KDIR / Module.symvers 的真实 LKM 构建与 MODPOST、真机 Root/KPM/Wi-Fi 测试均未完成。


## 98. 2026-11-12：将 packages.list refresh 移至真实 rename 完成点

### 发现与修复

此前 packages.list 更新监听使用 security_path_rename / security_inode_rename 的 after 回调，但它们只是 LSM 授权检查，执行时 VFS rename 尚未完成；LSM 返回成功不代表最终文件重命名成功。若后续 VFS rename 失败，旧实现仍可能提前读取 packages.list.tmp 并发布不对应已提交文件的 Manager UID。

已修复：
- 删除 pre-VFS LSM rename 监听，不再把授权检查结果当作 rename 成功。
- 目标设备 Linux 4.14.141 的原厂 KALLSYMS 记录确认 SyS_renameat2.cfi 存在（Image offset 0x003f4414），并且 sys_renameat2 是同一 syscall 的别名；Hook 改为精确的 CFI 函数体，不挂普通别名。
- before 回调只接受 flags=0 且旧路径精确为 /data/system/packages.list.tmp、新路径精确为 /data/system/packages.list 的调用，并把匹配状态保存在本次 hook local 中。
- after 回调只有在真实 syscall 返回 0 时才刷新，并读取已提交的 packages.list（use_tmp=0），不再读临时文件。
- Linux 4.14 的 rename / renameat 包装路径最终汇入 sys_renameat2；Hook 其 CFI 函数体后，回调发生在 syscall 完成清理、目录锁释放之后，避免在 VFS rename 持锁期间执行 APK / 文件 I/O。

### 回归验证

- 扩展 scripts/test_y73s_manager_uid_refresh.py，抽取真实 before/after 回调并编译执行：精确成功 rename 会刷新最终 packages.list；rename 失败、目标路径不匹配、非零 flags 均不会刷新。
- Fixture 现在模拟真实 KernelPatch hook_fargs5_t 前缀布局，并用 _Static_assert 检查 args 偏移为 88 bytes。
- scripts/verify_y73s_414_kallsyms_profile.py 将 SyS_renameat2.cfi 纳入目标设备必需符号；符号地址来自已保存的原厂 KALLSYMS 记录。
- Linux Host / 源码审计与 runtime fixture：Run [43219640474](https://github.com/ljx-91/kptools-fix/actions/runs/43219640474)，成功；rename 成功/失败/无关路径/flags 用例及 Manager UID generation 测试 PASS。
- Y73s GCC 14.2 KPIMG：Run [43219640512](https://github.com/ljx-91/kptools-fix/actions/runs/43219640512)，KPIMG build job 成功；同一 workflow 的 Windows kptools job 在本节更新时仍处于 MSYS2 setup 阶段，整条 workflow 尚未完成。
- Linux Host / kptools generic build：Run [43219640685](https://github.com/ljx-91/kptools-fix/actions/runs/43219640685)，成功。

### 限制

静态 KALLSYMS + Host fixture + KPIMG 交叉编译证明 Hook 目标和调用约定符合已保存的 Y73s 4.14.141 基线，但尚无真机 rename 事件日志。绝对路径精确匹配只覆盖 Android PackageManager 使用的该绝对路径替换形式；非零 rename flags 和其他路径故意不触发刷新。仍需设备日志确认实际 PackageManager 调用确实走该路径。

**当前源码/测试提交：** fcb9925117c67284f35009918adc8165838aaa30。
