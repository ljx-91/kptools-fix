# Y73s KPIMG 注入与 Hook 机器码审计（2026-11-14）

本报告针对同批次离线文件进行字节级复核：
- stock 解压内核：47,517,708 bytes
- patched 解压内核：47,826,896 bytes
- `kpimg-android`：304,976 bytes
- `kpimg-android.elf`：AArch64 ELF64

## 1. 内核入口和 KPIMG 注入

| 项目 | 结果 |
|---|---|
| Stock Image code0 | `0x1483c000`，B 目标 `0x020f0000` |
| Patched Image code0 | `0x14b54c00`，B 目标 `0x02d53000` |
| 嵌入 KPIMG raw 起点 | `0x02d52000` |
| KPIMG 执行入口 | raw + `0x1000`，即 `0x02d53000` |
| KPIMG raw 长度 | 304,976 bytes |
| KPIMG 后零填充 | 128 bytes |

KPIMG 在修补内核中的完整载荷与构建产物比较：113 个字节差异全部位于 raw 头部 `0x000–0x1f3` 的镜像专属 preset/config 字段；从 `0x200` 到载荷末尾逐字节一致。

原厂与修补后内核的共同长度区间，仅在 Image header code0（4 bytes）和 image_size 字段（实际变化 2 bytes）不同；其余共同区域逐字节一致。修补后 image_size 为 `0x038e8000`。

## 2. 关键符号机器码

- `paging_init` entry `0x01940228`：指令 `0x141eee95`，B 目标 `0x020fbc7c`，与此前确认的 CFI 函数体一致。
- `pid_vnr` entry `0x01912460`：指令 `0x17a025ec`，B 目标 `0x0011bc10`；这是 B veneer，入口不能直接当作函数体。
- Y73s 专用 `avc_denied` 31 条指令指纹在 stock kernel `0x0069141c` 全部匹配；调用点 `0x00691d74` 的 BL 目标也正好为 `0x0069141c`。

## 3. .setup.map 边界

- KPIMG ELF `.setup.map` 地址范围：`0xe400–0xecc0`，长度 `0x8c0`。
- 选定非 GKI map hole：`0x019352d0–0x019362d0`，长度 `0x1000`，完全位于 stock kernel image 内。
- 对 9 个函数符号检查了 79 条直接分支和 1 条 ADR/ADRP 引用，没有发现分支或 PC 相对引用离开复制区。

## 4. 结论与限制

静态检查确认：Image header 分支进入本次嵌入的 KPIMG 执行入口；KPIMG 代码主体未被意外改写；关键符号入口/CFI veneer 与 stock 内核字节吻合；映射代码直接分支未发现越界。

这些结果不证明运行时寄存器状态、memblock 分配器行为或 Hook 安装后执行正确。真机启动尚未验证；AVB 不属于本轮验收。当前镜像仍不应作为可刷入版本。
