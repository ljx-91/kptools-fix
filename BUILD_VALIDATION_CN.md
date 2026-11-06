# 构建与只读解析验证记录

验证对象：本目录 `KernelPatch-0.13.10-Y73S` 源码。

## 1. Linux 本机编译

命令：

```bash
cmake -S tools -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel 2
```

结果：`100% Built target kptools`，成功链接。版本命令输出 `d0a`（对应源码版本 0.13.10）。

编译器对上游 `tools/lib/sha/sha1.c` 的 `sha1_transform` 给出 `-Wstringop-overread` 诊断；该文件未在本次改动中修改，构建仍成功。此处保留该警告，不将其掩盖为零警告构建。

## 2. Vivo Y73s boot 只读检查

使用本次编译的 `kptools` 分别对用户提供的原版 `boot.img` 和 `new-boot-test.img` 执行 `unpack`，提取 gzip 内核，再对提取出的内核执行 `-d`。没有生成或写回 boot 镜像，也没有执行刷写。

| 项目 | 原版 boot | 修补后 boot |
|---|---:|---:|
| boot 文件长度 | 100663296 | 100663296 |
| 压缩 kernel 长度 | 16678904 | 16742278 |
| 解压 kernel 长度 | 47517708 | 47818256 |
| `kallsyms_num_syms` | `0x1a5b9` | `0x1a5b9` |
| `kallsyms_num_syms` offset | `0x01cef500` | `0x01cef500` |
| vectors index / offset | `18 / 0x2800` | `18 / 0x2800` |
| `pid_vnr` CFI stub 目标 | `0x0011bc10` | `0x0011bc10` |
| `pid_vnr` 检查指令 | `0xd5384108`（sp_el0） | `0xd5384108`（sp_el0）|
| `-d` 退出码 | 0 | 0 |

解释：严格 Kallsyms 解析在这两个输入上都通过，且得到了相同的关键符号表/CFI 定位结果。这只证明工具的静态符号解析路径可处理这两份内核，不证明 KPIMG 运行时初始化、内存映射、memblock ABI、厂商启动流程或整机启动兼容。

## 3. Windows 构建

源码内附 GitHub Actions 的 MSYS2 UCRT64 工作流。当前环境没有 Windows/MinGW 交叉编译器，因此没有在本机实测 Windows `.exe`。请以工作流实际产物为准。

## 4. 结论

- Linux 本机 CMake 构建通过。
- 原版与修补版 boot 的解压及严格 Kallsyms 只读检查通过。
- 未进行任何设备写入或实机启动测试；本项目不提供“一定可以开机”的保证。
