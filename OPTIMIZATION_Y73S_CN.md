# Vivo Y73s / MTK 4.14.141 定向优化说明（kptools 0.13.10）
> 当前分支的最新修复、CI 结果和未完成验证项统一记录在[Y73s 当前状态总览](Y73S_STATUS_CN.md)；本文仅说明 kptools 定向工具改动及其设计背景。


本目录以随用户提供的 KernelPatch 0.13.9 源码包为基础，保留官方源码的完整目录，并在工具端加入面向该设备日志特征的严格解析与镜像布局改进。它不是官方上游发布版，也不表示 APatch/KernelPatch 已经通过该设备的启动兼容性验证。

## 移植的改动

1. `tools/kallsym.c`：严格模式要求定位到可信的 `kallsyms_num_syms`；候选失败时清空计数并进入重试，不再用近似值硬解析。
2. `tools/kallsym.c`：ARM64 vectors 回退路径加入本次目标内核观察到的前三项地址一致性筛选；对不满足该特征的内核采取拒绝解析策略。该规则是目标内核定向启发式，不应视为所有 ARM64 内核的通用规则。
3. `tools/kallsym.c`：针对 CFI 跳板的 `pid_vnr` 入口检查，先识别直接 B 跳转并验证其目标函数入口。
4. `tools/patch.c`：注入 KPIMG 和 extra 区域后，扩大 ARM64 Image 头中的 `image_size` 声明，避免启动加载器将后续 DTB/initramfs 放入该区域而与早期复制目标重叠；解包/再次修补时用 preset 保存的原始 `kernel_size` 还原头字段。
5. `tools/bootimg.c`：当输出镜像需要扩展但尾部没有 rest 数据时，显式写入末尾填充字节，确保文件真实扩展到预期长度。
6. `tools/kptools.c` / `tools/patch.c`：日志默认隐藏 superkey 和 root-superkey verifier；新增通过文件描述符读入 key 的参数，避免把 key 放进命令行参数；提供显式 `--show-secrets` 仅用于 `-l` 镜像检查。

## 有意未合入的实验代码

先前的临时优化包还包含 BTF 扫描及 preset 中 BTF 偏移字段，但当前 KernelPatch 运行时源码没有与其配套的 BTF 消费路径。因此本完整源码分支没有保留这项未闭环改动，也没有改变官方 preset ABI。

## Windows 编译

使用 MSYS2 UCRT64 终端安装：

```bash
pacman -S --needed base-devel mingw-w64-ucrt-x86_64-gcc mingw-w64-ucrt-x86_64-cmake mingw-w64-ucrt-x86_64-make mingw-w64-ucrt-x86_64-zlib
```

在源码根目录运行：

```bash
cp -f kernel/include/preset.h tools/preset.h
cmake -S tools -B build -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release -DCMAKE_MAKE_PROGRAM=/ucrt64/bin/mingw32-make.exe -DZLIB_ROOT=/ucrt64
cmake --build build --parallel 2
./build/kptools.exe --version
```

GitHub Actions 也提供 Windows UCRT64 构建工作流，输出构建产物与 SHA256 校验文件。

## 验证边界

- 源码级：检查严格 Kallsyms 逻辑、preset ABI 未变化、关键改动的静态一致性。
- 编译级：本次交付附带的构建结果以实际 CI/本机编译记录为准；没有 CI 记录不能据此声称已在 Windows 上实测。
- 设备级：没有在 Vivo Y73s 实机上验证启动成功，不能承诺刷入后一定开机。尤其 `memblock` 函数参数 ABI、CFI 初始化时序、厂商启动链均仍需独立核验。

在任何设备测试前，应先保留原厂 boot 和恢复入口；不要把本源码包生成的镜像当作已经确认可启动的镜像。
