# Vivo Y73s KPIMG GCC audit branch

This branch contains an isolated Y73s audit change. It does not modify main.

- `kernel/base/start.c`: audited d0a restore immediate changed from 0x280 to 0x290. The workflow rejects any compiled binary whose actual frame layout does not match this assumption.
- `kernel/base/map.c`: comment corrected using the original Y73s 4.14.141 CFI entry disassembly; no runtime argument behavior changed.
- `scripts/verify_kpimg_stack_frame.py`: fail-closed static verifier.
- `.github/workflows/build-y73s-kpimg-gcc.yml`: downloads Arm GNU Toolchain 12.2.rel1, builds Android KPIMG and uploads raw KPIMG, ELF, verification log and hashes.

This is not a flashable boot image. A passing build is not device boot validation. AVB, boot image repacking, Vivo boot-chain behavior and real-device cold boot remain unverified. Do not flash an artifact solely because CI passes.
