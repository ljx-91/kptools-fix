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
| KPIMG SHA-256 | `a7ac08f0bec60508bc9ad1e60e3cbff10cf79a7d617300861bf7b9faaf2f45d8` |
| Android kptools SHA-256 | `c6007cee6e813717309731c83f73ee20acd5147a58bc844e572dabc76f483177` |
| KPIMG 源码提交 | `46da4883f8e97b62212a2d72fd82677dfc9ee221` |
| APK 工作流提交 | `ca67a8c35337d04d5ac0b45f681857b23950545f` |
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
| 压缩 kernel size | 16,678,904 | 16,747,419 |
| 解压 kernel size | 47,517,708 | 47,826,896 |
| ramdisk size | 777,508 | 777,508 |
| DTB size | 158,376 | 158,376 |

- ramdisk SHA-256 两边一致：`f14df852dfc9d2dc7fe17edfbceedb564d616b19e2ace7ef0f633d94798065dc`。
- DTB SHA-256 两边一致：`a285f5057385bede3f52698bdc6de34fdbc6edae485f311ee1ab4484279654a5`。
- 原厂解压 kernel 的共同前缀中，实际只有 4 个字节不同：offset `0x1`、`0x2`（Image code0 指令立即数）及 `0x11`、`0x12`（image_size 字段）；其余共同前缀字节相同。
- 修补后 Boot SHA-256：`c76a7b96cae1326ae45d45b1be7950435b3be1160f9a58c3362e3352f74fd187`。
- 对修补后 Boot 再次执行 `kptools unpack` 成功，解压 kernel 为 47,826,896 bytes；`kptools -i kernel -l` 识别 `patched=true`、KPIMG version `0xd0a`。

## setup1.S 早期 preset 预检

在本次构建中，`start_prepare` 增加了早期 fail-closed 检查，执行顺序早于第一次从 kernel 区域备份或复制数据：

- `kpimg_size` 必须覆盖 `_kp_start - _link_base` 的 setup 前缀。
- 派生的 `start_img_size` 必须非零、16 字节对齐，并且不超过 `_kp_end - _kp_start`。
- `extra_size` 必须非负且 16 字节对齐；`start_img_size + extra_size` 检查溢出并确保 4 字节对齐，满足 `rmemcpy32` 的复制约束。
- `start_offset` 必须按 4 KiB 对齐，且整个 start/extra 复制范围必须落在扩展后的 kernel Image 大小内。
- map backup 长度不得超过固定 `MAP_MAX_SIZE`，其源区间必须位于 kernel Image 范围内。
- 所有不满足条件的分支统一跳转到 `.bad_paging_init`（`brk #0`），原有 `_paging_init` C 层大小保护仍保留。

新增的 `scripts/verify_y73s_setup_preset_bounds.py` 已在 combined workflow 的 regression-test 步骤通过。使用带该预检的 KPIMG 对原厂 Boot 再次离线修补、二次解包和 Patch-only 手动流程复现均成功；手动流程输出与直接 patch 输出逐字节一致。

## 与 FolkPatch 默认 Patch-only 流程对照

- FolkPatch 115404 的 `PatchesViewModel` 默认 SuperKey 为 `su`；`boot_patch.sh` 对 `su` 不添加 `-S`。本次离线测试同样未传 `-S`，与默认签名管理器路径一致。
- 按 APK 脚本的实际顺序执行 `unpack -> kptools -p -i kernel.ori -k kpimg -o kernel -> repack`，生成的 `new-boot.img` 与直接对 Android Boot 执行 `kptools --patch -i boot.img -k kpimg -o output` 的 SHA-256 完全相同：`c76a7b96cae1326ae45d45b1be7950435b3be1160f9a58c3362e3352f74fd187`。
- FolkPatch 的 Patch-only 模式不传 `FLASH_TO_DEVICE=true`，不会执行脚本中的刷写分支。
- 因 `CONFIG_KALLSYMS_ALL=n`，APK 内上游脚本会显示通用风险提示；本次 kptools 的 Y73s 严格 vector / 指纹解析成功，但不能因此消除运行时启动风险。
- KPIMG 的可信管理器 pin 指向官方 `me.yuki.folk` 签名。Y73s patcher APK 使用并列包名 `me.yuki.folk.y73s.patcher`，不能替代官方管理器；需要保留官方 FolkPatch 管理器安装。

## Unpatch / 回滚路径检查

- 对修补后解压出的 kernel 执行 `kptools --unpatch`，得到 47,517,708 bytes 的 kernel；SHA-256 与原厂解压 kernel 完全一致：`345bfab8217669cb84ed004916efea4fae06e6b169c70e1be2ec9ac3ad4f093e`。
- 将该 kernel 重新 repack 后，Boot 容器不再与原厂文件逐字节相同（新文件 SHA-256：`0c076c7e2ca83e2dec208c500c504f96ad424a07d6235058ba37726825e6f363`）。原因是 GZIP 流重新压缩、kernel_size / vbmeta_offset 随之变化；AVB digest/signature 也没有重新计算。
- 因此，`kptools --unpatch` 可以精确恢复解压后的原厂 kernel 内容，但不能替代保存原始 `boot.img`。回滚必须保留原厂 Boot 备份；不能把重新 repack 的 unpatched image 当作原厂字节级备份。

## AVB 与安全限制

- 原厂 footer：`original_image_size=17,618,944`，`vbmeta_offset=17,620,992`，`vbmeta_size=1,472`。
- 修补后 footer：`original_image_size=17,688,576`，`vbmeta_offset=17,690,624`，`vbmeta_size=1,472`。
- vbmeta 原始区域移动后 SHA-256 保持一致：`5374b5d334a275eb682ec80f87345468e0994e0fa1c0c611d37196e062b6ed85`。
- AVB digest/signature 没有重新计算。工具也明确警告该镜像不是 AVB-verified。

**最终判定：离线工具链、符号解析、KPIMG 注入位置、ramdisk/DTB 保持、二次解包均通过；AVB 未验证，运行时 Hook/真机启动未验证。此文件仅供诊断，不可刷入。**
