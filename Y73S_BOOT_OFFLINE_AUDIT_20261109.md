# Vivo Y73s 原始 Boot 离线审计（2026-11-09）

> 范围：仅对资料库中的 `boot.img`、`vbmeta.img`、`vbmeta_system.img` 和 `vivo-y73s-kpimg-test-boot.img` 做只读解析。未连接设备，未执行 Fastboot、刷写、分区写入或启动测试。候选镜像仅供离线分析，禁止据此认定可启动或可刷入。

## 1. 输入文件身份

| 文件 | 大小 | SHA-256 |
|---|---:|---|
| `boot.img` | 100,663,296 | `c47e94f64696fe70de11ea26cda4a3e0e6e025e581e7a96b95f1d975c9fe7cd5` |
| `vbmeta.img` | 8,192 | `9dea25766afba4fbaf601e80ae73bd69637d15aa40ae13a468312a8bb90aa652` |
| `vbmeta_system.img` | 4,096 | `8463fe5995be29055e9bf35483110e9eeecf80fbfb1af34953631ba883fcfa12` |
| `vivo-y73s-kpimg-test-boot.img` | 100,663,296 | `bf6c0daf9da839acb219f2b5cfba2670f7536eacaad0d42164cb08d3765640ca` |

## 2. 原始 Boot 结构

- Android magic：`ANDROID!`；Boot Header v2；page size：2,048。
- Header 字段：kernel size 16,678,904；ramdisk size 777,508；second size 0；DTB table size 158,376；header size 1,660。
- 按页对齐解析出的布局：kernel offset 2,048；ramdisk offset 16,680,960；DTB table offset 17,459,200；DTB table 结束于 17,617,576。
- DTB table magic 为 `0xd7b7ab1e`，包含 1 个 entry；entry 的 DTB size 为 158,312、offset 为 64。表内 DTB 从 `0xd00dfeed` 开始。
- Kernel 区域的 gzip member 可完整解压为 47,517,708 字节；gzip member 后附带的 158,312 字节与独立 DTB table entry 的 DTB 内容逐字节相同。
- 解压后的 ARM64 Image header magic 为 `ARMd`。内核版本字符串为 Linux 4.14.141+；编译器字符串指向 Android Clang 9.0.3。
- 内核内嵌 `IKCFG_ST` / `IKCFG_ED`，配置可成功解压，确认关键配置：
  - `CONFIG_ARM64=y`、`CONFIG_ARM64_4K_PAGES=y`、`CONFIG_ARM64_VA_BITS=39`
  - `CONFIG_MODULES=y`、`CONFIG_MODULE_UNLOAD=y`、`CONFIG_MODVERSIONS=y`
  - `CONFIG_KALLSYMS=y`、`CONFIG_KALLSYMS_ALL` 未启用、`CONFIG_KPROBES` 未启用
  - `CONFIG_LTO_CLANG=y`、`CONFIG_CFI=y`、`CONFIG_CFI_CLANG=y`、`CONFIG_CFI_CLANG_SHADOW=y`
  - `CONFIG_DEBUG_INFO=y`、`CONFIG_IKCONFIG=y`、`CONFIG_IKCONFIG_PROC=y`

### 对 LKM/KPM 工作的影响

1. 目标确认为 ARM64、4KB pages、VA_BITS=39 的 Linux 4.14.141 vendor kernel；不能用 Android 12/Linux 5.10 的通用 DDK 结果替代。
2. `CONFIG_MODVERSIONS=y` 意味着真实 .ko 编译/加载验证需要匹配的生成头文件、`Module.symvers` 和目标 Kbuild 配置。
3. LTO + Clang CFI + CFI shadow 是必须单独审计的 ABI/间接调用约束。当前主机端源码契约审计并没有证明目标 .ko 或自定义 KPM ELF 满足该内核的 CFI 约束。
4. `CONFIG_KPROBES` 未启用；不能假定可用基于 Kprobes 的替代 hook 路径。
5. 该配置仍不能替代完整目标 KDIR、生成头文件、`Module.symvers`、精确工具链和实际目标构建。

## 3. AVB 原始镜像核对

- 原始 Boot Footer：`original_image_size=17,618,944`、`vbmeta_offset=17,620,992`、`vbmeta_size=1,472`。
- 原始 Boot 内嵌 VBMeta SHA-256：`5374b5d334a275eb682ec80f87345468e0994e0fa1c0c611d37196e062b6ed85`。
- 使用原始 Boot descriptor 的 salt `aee087a5be3b982978c923f566a94613496b417f2af592639bc80d141e34dfe7` 对前 17,618,944 字节计算 SHA-256，结果为 `36a3d398fc5a5350e1642f54584ebca8d06e20644e622993f9547e057467623c`，与此前 AVB 审计记录的 descriptor digest 完全一致。
- 这确认当前资料库 `boot.img` 与已记录的原始 Boot HashDescriptor 内容匹配。根 vbmeta / vbmeta_system 的 OEM 信任链和签名判断仍以单独 AVB chain audit 为准。

## 4. 已有 KPIMG 候选镜像复核

针对 SHA-256 为 `bf6c0daf9da839acb219f2b5cfba2670f7536eacaad0d42164cb08d3765640ca` 的 `vivo-y73s-kpimg-test-boot.img`：

- Android Boot Header 仍为 v2 / page size 2,048；kernel size 16,742,275；ramdisk size 776,315。
- gzip kernel member 解压为 47,818,256 字节；KPIMG 标识 `KP1158` 位于解压后偏移 `0x2d52000`。
- 原始与候选 ramdisk 解压后的 1,789,440 字节完全一致，SHA-256 均为 `d92343f51d6aac342d27aebec7ac1ff5bbed60e3808dc6669c345068cab668de`。
- 候选 Boot Footer 实际解析值为 `original_image_size=17,682,432`、`vbmeta_offset=17,684,480`、`vbmeta_size=1,472`；嵌入 VBMeta blob SHA-256 仍为原始的 `5374b5d334a275eb682ec80f87345468e0994e0fa1c0c611d37196e062b6ed85`。
- 用原始 descriptor 对候选镜像前 17,618,944 字节计算，摘要为 `2fc9dd767df46ccdd07d96f5cf441b21cdb2dacb30055eea5f4b1887ed371a52`，不匹配原始 descriptor digest。候选镜像没有重新签署 boot descriptor，不能宣称 AVB 验证通过。

### 历史报告数值差异

旧文件 `y73s-original-boot-kpimg-offline-injection-report.txt` 记录的候选 Footer 为 `original_image_size=17,680,384`、`vbmeta_offset=17,682,432`；但本次对资料库中上述确切 SHA-256 的候选文件直接解析，结果分别为 17,682,432 和 17,684,480，相差 2,048 字节。旧报告还记录 kptools unpack 后长度 47,818,272，而本次对候选 Boot 中 gzip member 直接解压得到 47,818,256，相差 16 字节。两组记录不能混为同一产物；后续审计应以文件 SHA-256 绑定证据，并查明旧报告对应的确切 artifact。\n\n资料库中的旧日志 \`vivo-y73s-kpimg-patch-test.log\` 还记录 kernel size 为 16,661,916；但本次 SHA-256 为 \`c47e94f6…c9fe7cd5\` 的原始 \`boot.img\` Header 实际为 16,678,904。两者解压后的 gzip kernel member 长度都记录为 47,517,708，但 Header kernel-size 字段相差 16,988 字节。该日志不应继续作为当前这份原始 Boot 的 Header 解析依据，需追溯其输入文件 SHA 或旧版 kptools 的解析逻辑。

## 5. 结论与未完成项

- 原始 Boot、DTB table、内嵌 kernel config 和 AVB Boot descriptor 已获得可复核的离线证据。
- 当前最重要的新兼容性约束是目标内核启用了 LTO、Clang CFI、CFI shadow 和 MODVERSIONS，同时未启用 Kprobes。
- 下一步应获取精确匹配的 4.14.141 kernel source/build tree、生成头文件、`Module.symvers`、config 和 Clang 9.0.3 工具链，再针对 CFI/LTO/MODVERSIONS 审计并构建 LKM。
- 仍未完成目标 KDIR 编译、动态 KPM 加载、设备启动、APatch 初始化或 root 验证。
- 不执行 Fastboot、刷写、boot/vbmeta 修改或任何设备分区写入。


## 6. 目标配置与当前 LKM/Kbuild 编译参数的交叉审计（2026-11-09 更新）

本轮直接从上述原始 Boot 的 gzip kernel member 解压出 ARM64 Image，再从 Image 内部 IKCFG_ST / IKCFG_ED 容器解压 .config；编译器版本来自同一 Image 内的 Linux version 字符串。可复核结果：

- 编译器：Android Clang 9.0.3；LLD 9.0.3。
- `CONFIG_CFI=y`、`CONFIG_CFI_CLANG=y`、`CONFIG_CFI_CLANG_SHADOW=y`、`CONFIG_LTO_CLANG=y` 均已设置。
- 在该 .config 中未发现 `CONFIG_SHADOW_CALL_STACK` 或 `CONFIG_ARM64_BTI_KERNEL`；这不代表 CPU 或内核绝不支持相应指令，只说明本次解析的配置没有启用对应内核选项。

### 已完成的 Kbuild 修正

此前 `lkm/Kbuild` 对 `hook/hook_engine.o` 无条件追加 BTI 和 SCS 参数。本轮已提交条件化处理：

- 仅当 `CONFIG_ARM64_BTI_KERNEL=y` 时添加 `-mbranch-protection=bti`。
- 仅当 `CONFIG_SHADOW_CALL_STACK=y` 或 `CONFIG_ARM64_SCS=y` 时添加 `-fno-sanitize=shadow-call-stack`。
- 保留 Hook engine 的 `-fno-lto` 与 CFI 隔离策略，不擅自推断其对目标内核已经兼容。

因此按当前 Boot .config，Y73s 4.14.141 构建不会再无条件收到 BTI/SCS 参数。该条件化逻辑已纳入 Host 源码契约审计；KPIMG 构建和全量源码审计已通过。

### 仍需目标 KDIR 证明的事项

**审计判断：** 上述参数修正只解决了不必要的 BTI/SCS 强制参数问题，并未证明模块的 CFI/LTO ABI 已完全兼容。目标启用了 CFI、CFI shadow、LTO 和 MODVERSIONS；仍需核对真实 Kbuild 编译命令、CFI type metadata/shadow ABI、LTO plugin/link flags、模块版本 CRC，以及 Hook engine 对 CFI 的隔离是否正确。

**下一步必要输入：** 与此 Boot 完全对应的 4.14.141 kernel source/build tree、`.config`、`Module.symvers`、生成头文件和 Clang/LLD 9.0.3 工具链。拿到后先执行 `make V=1` dry-run/compile-command 审计，再真实编译和 modpost。不得用通用 DDK 示例成功结果替代。


## 7. 模块强制卸载配置的直接核验（2026-11-10）

本轮重新从资料库中的 `vivo-y73s-4.14.141-extracted(1).config` 原始配置文件读取并检查，文件 SHA-256：

`f70215f43982b627eac9021aca8f9f1c47035c0c97890bee73adabdb2ec3cb8d`

精确配置项为：

- `CONFIG_MODULES=y`
- `CONFIG_MODULE_UNLOAD=y`
- `# CONFIG_MODULE_FORCE_UNLOAD is not set`

对照 `gregkh/linux` 的精确 `v4.14.141` `kernel/module.c`：
- `try_force_unload()` 在未定义 `CONFIG_MODULE_FORCE_UNLOAD` 时固定返回 0。
- `try_stop_module()` 在移除模块基础引用后若仍有额外引用，会因 `!(*forced)` 返回 `-EWOULDBLOCK`，不会把模块状态切换为 `MODULE_STATE_GOING`。
- 因而在该目标配置下，模块持有额外引用可以阻止普通卸载，也不存在通过 `delete_module(O_TRUNC)` 强制越过引用计数的配置路径。

这项配置事实来自已提取的原始 Boot 内嵌 IKCONFIG；它不替代 vendor KDIR 的模块构建验证。
