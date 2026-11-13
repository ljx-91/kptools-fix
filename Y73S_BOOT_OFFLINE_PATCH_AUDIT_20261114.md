# vivo Y73s 原厂 Boot 离线修补验收（2026-11-14）

## 结论边界

本报告记录对资料库原厂 Boot 的离线修补与二次解包核验。它证明当前分支的 kptools 能识别这份 Y73s 原厂镜像、通过严格符号解析并生成结构可再次解包的 patched boot；**不证明设备能够启动、KernelPatch 能在运行时完成所有 Hook，也不是可刷入镜像**。

- 未连接设备、未执行 fastboot/recovery/9008、未刷写任何分区。
- AVB 按项目要求未修复。工具明确警告 vbmeta 元数据虽被保留，但分区摘要和签名没有重新计算。
- 本次命令未传 `-S`。工具日志为 `root_key mode with empty superkey: root_superkey zeroed`；这是离线测试的默认 manager 模式，不代表已经验证应用实际授权交互。

## 输入、工具与产物身份

| 项目 | 值 |
|---|---|
| 目标 | vivo Y73s V2031A / PD2031 / MT6853 |
| 原厂系统 | Android 10，Linux 4.14.141+ |
| 原厂 Boot SHA-256 | `c47e94f64696fe70de11ea26cda4a3e0e6e025e581e7a96b95f1d975c9fe7cd5` |
| 原厂 Boot 大小 | 100,663,296 bytes |
| kptools host | Linux x86_64，version `d0a`（0.13.10） |
| kptools host SHA-256 | `0185603100f0cc7f97ea27fe9f85bb6f9d7504e3368c8f7a311c16b62065b927` |
| KPIMG | 0.13.10，Android / ARM64 / release |
| KPIMG SHA-256 | `297b2432acc4aa1108720cae2667f75a121fd5dd459b41795d041618ad382a21` |
| Android kptools SHA-256 | `c6007cee6e813717309731c83f73ee20acd5147a58bc844e572dabc76f483177` |
| KPIMG/APK 构建提交 | `cdfc3fde652076951e55361f6cd1c0a3c918b29e` |
| Linux host kptools 工作流提交 | `6133b31f57a6a72e8bcc442d1c1e23e8c8b7f628` |

host 工具提交相对 KPIMG/APK 提交只新增了 host 构建 workflow 文件，工具源码树没有变化。

## kptools 解析与符号解析

- 识别 Android Boot Header v2，page size 2048，GZIP kernel。
- 解压原厂 kernel 为 47,517,708 bytes。
- 识别 Linux 4.14.141+、非 GKI、ARM64。
- `CONFIG_KALLSYMS=y`，`CONFIG_KALLSYMS_ALL=n`。
- 严格 Kallsyms / ARM64 vector fallback 成功：
  - `kallsyms_num_syms=0x1a5b9`（107,961）。
  - `kallsyms_addresses=0x01c1c700`。
  - `vectors` index 18，offset `0x2800`。
  - `pid_vnr` offset `0x01912460`，识别 CFI B veneer 到 `0x0011bc10`，并验证 SP_EL0 指令 `0xd5384108`。
- Y73s 专用 `avc_denied` 不在 KALLSYMS 中；31 指令指纹验证成功，offset `0x0069141c`。
- 解析的关键偏移：
  - `kallsyms_lookup_name=0x01922680`
  - `paging_init=0x01940228`
  - `map_start=0x019352d0`
  - `memblock_find_in_range=0x01914914`
  - `memblock_virt_alloc_try_nid_nopanic=0x0191492c`
  - `memblock_reserve=0x019282d8`
  - `memblock_free=0x019282d4`
  - `memblock_mark_nomap=0x019282e8`
- map 区域选择为 `0x019352d0`，最大长度 `0x1000`。
- 没有 `kernel_init` 符号时，工具从 `rest_init` 的 kernel_thread 调用点解析；这一路径成功。

## 注入和 Image 入口

- KPIMG raw 起点：`0x02d52000`。
- KPIMG 长度：304,976 bytes（`0x4a750`）。
- Image code0 指令：`0x14b54c00`，解码 B 位移为 `0x02d53000`。
- KPIMG 执行入口：raw + `0x1000` = `0x02d53000`，与 Image 入口跳转目标一致。
- KPIMG 嵌入副本与构建产物有 113 bytes 差异，全部在镜像专属 preset/config 头部 `0x41–0x1f3`；从 `0x200` 到载荷末尾逐字节一致。
- 额外数据区为 128 bytes 的空终止项。
- 修补后的 Image `image_size=0x038e8000`，覆盖本次 KPIMG 与额外数据的复制范围。

## 原厂与修补后 Boot 对比

| 项目 | 原厂 | 修补后 |
|---|---:|---:|
| Boot 文件大小 | 100,663,296 | 100,663,296 |
| Header version | 2 | 2 |
| Page size | 2048 | 2048 |
| 压缩 kernel size | 16,678,904 | 16,747,274 |
| 解压 kernel size | 47,517,708 | 47,826,896 |
| ramdisk size | 777,508 | 777,508 |
| DTB size | 158,376 | 158,376 |

- ramdisk SHA-256 两边一致：`f14df852dfc9d2dc7fe17edfbceedb564d616b19e2ace7ef0f633d94798065dc`。
- DTB SHA-256 两边一致：`a285f5057385bede3f52698bdc6de34fdbc6edae485f311ee1ab4484279654a5`。
- 原厂解压 kernel 的共同前缀中，实际只有 4 个字节不同：offset `0x1`、`0x2`（Image code0 指令立即数）及 `0x11`、`0x12`（image_size 字段）；其余共同前缀字节相同。
- 修补后 Boot SHA-256：`21488cadb09b99e49d6a33ff13ef1e0644ee779d72a1db70e0cbb4a8f8428a9a`。
- 对修补后 Boot 再次执行 `kptools unpack` 成功，解压 kernel 为 47,826,896 bytes；`kptools -i kernel -l` 识别 `patched=true`、KPIMG version `0xd0a`。

## AVB 与安全限制

- 原厂 footer：`original_image_size=17,618,944`，`vbmeta_offset=17,620,992`，`vbmeta_size=1,472`。
- 修补后 footer：`original_image_size=17,688,576`，`vbmeta_offset=17,690,624`，`vbmeta_size=1,472`。
- vbmeta 原始区域移动后 SHA-256 保持一致：`5374b5d334a275eb682ec80f87345468e0994e0fa1c0c611d37196e062b6ed85`。
- AVB digest/signature 没有重新计算。工具也明确警告该镜像不是 AVB-verified。

**最终判定：离线工具链、符号解析、KPIMG 注入位置、ramdisk/DTB 保持、二次解包均通过；AVB 未验证，运行时 Hook/真机启动未验证。此文件仅供诊断，不可刷入。**
