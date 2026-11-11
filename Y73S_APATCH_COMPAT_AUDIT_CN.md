# vivo Y73s APatch / KernelPatch 4.14.141+ 兼容性审计

日期：2026-11-12  
仓库：ljx-91/kptools-fix  
分支：y73s-cred-layout-guards-20261108  
本轮代码 HEAD：bbaa8e39c3b9ed054acfc60067d4f8382f82a3ba

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

- Linux Host kptools + 仓库源码契约：Run [43071269698](https://github.com/ljx-91/kptools-fix/actions/runs/43071269698)，成功；日志包含 Y73s AVC 指纹检查全部 PASS。
- Y73s GCC 14.2 Android KPIMG：Run [43071269821](https://github.com/ljx-91/kptools-fix/actions/runs/43071269821)，成功。
- Windows kptools：Run [43071269905](https://github.com/ljx-91/kptools-fix/actions/runs/43071269905)，构建、DLL 收集、Smoke Test 和 ZIP 打包步骤均已完成；最终 workflow 状态需以 GitHub Actions 页面为准。
- 仅修正日志换行后的最新 Linux Host run：[43071760192](https://github.com/ljx-91/kptools-fix/actions/runs/43071760192)，成功。

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
