/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 */

#include "symbol.h"
#include "common.h"
#include "insn.h"

struct on_each_symbol_struct
{
    const char *symbol;
    uint64_t addr;
};

static int32_t on_each_symbol_callbackup(int32_t index, char type, const char *symbol, int32_t offset, void *userdata)
{
    struct on_each_symbol_struct *data = (struct on_each_symbol_struct *)userdata;
    int len = strlen(data->symbol);
    if (strstr(symbol, data->symbol) == symbol && (symbol[len] == '.' || symbol[len] == '$') &&
        !strstr(symbol, ".cfi_jt")) {
        tools_logi("%s -> %s: type: %c, offset: 0x%08x\n", data->symbol, symbol, type, offset);
        data->addr = offset;
        return 1;
    }
    return 0;
}

int32_t find_suffixed_symbol(kallsym_t *kallsym, char *img_buf, const char *symbol)
{
    struct on_each_symbol_struct udata = { symbol, 0 };
    on_each_symbol(kallsym, img_buf, &udata, on_each_symbol_callbackup);
    return udata.addr;
}

int32_t get_symbol_offset_zero(kallsym_t *info, char *img, char *symbol)
{
    int32_t offset = get_symbol_offset(info, img, symbol);
    return offset > 0 ? offset : 0;
}

int32_t get_symbol_offset_exit(kallsym_t *info, char *img, char *symbol)
{
    int32_t offset = get_symbol_offset(info, img, symbol);
    if (offset >= 0) {
        return offset;
    } else {
        tools_loge_exit("no symbol %s\n", symbol);
    }
}

int32_t try_get_symbol_offset_zero(kallsym_t *info, char *img, char *symbol)
{
    int32_t offset = get_symbol_offset(info, img, symbol);
    if (offset > 0) return offset;
    return find_suffixed_symbol(info, img, symbol);
}

static int get_cand_arr_symbol_offset_try(kallsym_t *kallsym, char *img_buf, const char **cand_arr, int cand_num,
                                          const char **selected)
{
    int offset = 0;

    for (int i = 0; i < cand_num; i++) {
        offset = try_get_symbol_offset_zero(kallsym, img_buf, (char *)cand_arr[i]);
        if (offset) {
            if (selected) *selected = cand_arr[i];
            return offset;
        }
    }

    if (selected) *selected = 0;
    return 0;
}

bool is_usable_symbol_offset(int32_t offset, int imglen)
{
    return imglen >= 0x1000 && offset > 0 && offset <= imglen - 0x1000;
}

int32_t get_usable_symbol_offset_try(kallsym_t *kallsym, char *img_buf, int imglen, const char *symbol)
{
    int32_t offset = get_symbol_offset_zero(kallsym, img_buf, (char *)symbol);
    if (is_usable_symbol_offset(offset, imglen)) {
        return offset;
    }

    offset = find_suffixed_symbol(kallsym, img_buf, symbol);
    if (is_usable_symbol_offset(offset, imglen)) {
        return offset;
    }

    return 0;
}

int32_t select_symbol_lookup_anchor_offset(kallsym_t *kallsym, char *img_buf, int imglen, const char **selected)
{
    static const char *anchor_candidates[] = {
        "show_stack",
        "dump_backtrace",
        "nmi_panic",
        "panic",
        "show_freq_kernel_log",
        "input_handle_event",
        "slow_avc_audit",
        "avc_denied",
        "tcp_init_sock",
        "udp_init_sock",
        "inet_create",
        "inet_release",
        "sock_init_data",
        "sk_alloc",
    };

    for (int i = 0; i < (int)(sizeof(anchor_candidates) / sizeof(anchor_candidates[0])); i++) {
        const char *name = anchor_candidates[i];
        int32_t offset = get_usable_symbol_offset_try(kallsym, img_buf, imglen, name);
        if (offset) {
            if (selected) *selected = name;
            return offset;
        }
    }

    if (selected) *selected = 0;
    return 0;
}

static int32_t get_map_anchor_offset(kallsym_t *kallsym, char *img_buf, int imglen, const char **selected)
{
    static const char *map_anchor_candidates[] = {
        "tcp_init_sock",
        "udp_init_sock",
        "inet_create",
        "inet_release",
        "sock_init_data",
        "sk_alloc",
        "input_handle_event",
        "slow_avc_audit",
        "avc_denied",
        "nmi_panic",
        "panic",
        "kern_addr_valid",
        "set_memory_rw",
        "set_memory_ro",
        "free_initmem",
    };

    for (int i = 0; i < (int)(sizeof(map_anchor_candidates) / sizeof(map_anchor_candidates[0])); i++) {
        const char *name = map_anchor_candidates[i];
        int32_t offset = get_usable_symbol_offset_try(kallsym, img_buf, imglen, name);
        if (offset) {
            if (selected) *selected = name;
            return offset;
        }
    }

    if (selected) *selected = 0;
    return 0;
}

// todo
void select_map_area(kallsym_t *kallsym, char *image_buf, int imglen, int32_t *map_start, int32_t *max_size, bool is_gki)
{
    if (!kallsym || !image_buf || imglen <= 0 || !map_start || !max_size) {
        tools_loge_exit("invalid map selection inputs\n");
    }

    const char *selected = 0;
    int32_t addr = get_map_anchor_offset(kallsym, image_buf, imglen, &selected);
    if (addr <= 0 || addr >= imglen || (addr & 3)) {
        tools_loge_exit("invalid or unaligned map anchor: %d\n", addr);
    }
    tools_logi("select map anchor: %s, offset: 0x%08x\n", selected, addr);

    // The hole must hold the whole map section (map_data + map code,
    // currently ~0xf10 with the scratch machinery) so the map_prepare copy
    // never spills over the NOP-synced area into untouched kernel code.
    // start_prepare backs up and restore_map restores exactly map_max_size
    // bytes, so every NOPed byte comes back.  MAP_HOLE_OVERRIDE exists to
    // build a bisect variant with the legacy 0x800 hole.
#ifdef MAP_HOLE_OVERRIDE
    int32_t hole_size = MAP_HOLE_OVERRIDE;
#else
    int32_t hole_size = MAP_MAX_SIZE;
#endif
    if (hole_size <= 0 || (int64_t)hole_size * 2 > imglen) {
        tools_loge_exit("invalid map hole size %d for image length %d\n", hole_size, imglen);
    }

    if (!is_gki) {
        // Non-GKI kernels use the area immediately after a cold text symbol.
        int64_t aligned_start = ((int64_t)addr + 15) & ~15LL;
        if (aligned_start + hole_size > imglen) {
            tools_loge_exit("non-GKI map hole exceeds image: start=0x%llx size=0x%x image=0x%x\n",
                            (unsigned long long)aligned_start, hole_size, imglen);
        }
        *map_start = (int32_t)aligned_start;
        *max_size = hole_size;
        return;
    }

    // PAC scanning may inspect a second window when the first window has an
    // unmatched instruction.  Validate the complete two-window range first.
    if ((int64_t)addr + (int64_t)hole_size * 2 > imglen) {
        tools_loge_exit("GKI PAC scan exceeds image: anchor=0x%x size=0x%x image=0x%x\n",
                        addr, hole_size, imglen);
    }
    *map_start = align_floor(addr, 16);
    if ((int64_t)*map_start + hole_size > imglen) {
        tools_loge_exit("GKI map hole exceeds image: start=0x%x size=0x%x image=0x%x\n",
                        *map_start, hole_size, imglen);
    }
    *max_size = hole_size;

#define NOP 0xD503201F
#define PAC 0xd503233f
#define AUT 0xd50323bf
#define PAC_MASK 0xFFFFFD1F
#define PAC_PATTERN 0xD503211F

    uint32_t pos = 0;
    uint32_t count = 0;
    uint32_t asmbit = sizeof(uint32_t);
    bool is_first_pac = false;
    for (uint32_t i = 0; i < (uint32_t)*max_size; i += asmbit) {
        uint32_t insn;
        memcpy(&insn, image_buf + addr + i, sizeof(insn));
        if (!is_first_pac && insn == PAC && i < asmbit * 5) {
            is_first_pac = true;
        }
        if ((insn & PAC_MASK) == PAC_PATTERN) {
            pos = i;
            count++;
            uint32_t nop = NOP;
            memcpy(image_buf + addr + pos, &nop, sizeof(nop));
        }
    }

    if (!is_first_pac) {
        tools_logi("no first pac instruction found\n");
    }

    if (count % 2 != 0) {
        tools_logi("pac verify not pair pos: %x count: %d\n", pos, count);

        uint32_t second_pos = 0;
        for (uint32_t j = (uint32_t)*max_size; j < (uint32_t)*max_size * 2; j += asmbit) {
            uint32_t insn;
            memcpy(&insn, image_buf + addr + j, sizeof(insn));
            if ((insn & PAC_MASK) == PAC_PATTERN) {
                second_pos = j;
                break;
            }
        }
        if (!second_pos) {
            tools_loge_exit("unpaired PAC instruction has no matching instruction in second map window\n");
        }
        tools_logi("second_pos: %x\n", second_pos);
        uint32_t nop = NOP;
        memcpy(image_buf + addr + second_pos, &nop, sizeof(nop));
    }

#undef NOP
#undef PAC
#undef AUT
#undef PAC_MASK
#undef PAC_PATTERN
}

int fillin_map_symbol(kallsym_t *kallsym, char *img_buf, map_symbol_t *symbol, int32_t target_is_be)
{
    memset(symbol, 0, sizeof(*symbol));
    /*
     * These three interfaces are required by the Y73S relocation path and
     * have verified two-argument ABIs. Do not substitute an internal
     * __memblock_reserve helper whose prototype may differ across kernels.
     */
    symbol->memblock_reserve_relo = get_symbol_offset_zero(kallsym, img_buf, "memblock_reserve");
    symbol->memblock_free_relo = get_symbol_offset_zero(kallsym, img_buf, "memblock_free");
    symbol->memblock_mark_nomap_relo = get_symbol_offset_zero(kallsym, img_buf, "memblock_mark_nomap");

    if (!symbol->memblock_reserve_relo) {
        tools_loge_exit("no verified two-argument memblock_reserve symbol\\n");
    }
    if (!symbol->memblock_free_relo) {
        tools_loge_exit("no verified two-argument memblock_free symbol\\n");
    }
    if (!symbol->memblock_mark_nomap_relo) {
        tools_loge_exit("no verified two-argument memblock_mark_nomap symbol\\n");
    }

    /*
     * Prefer the range finder when available. Unlike memblock_alloc_try_nid,
     * memblock_find_in_range returns a physical address; map.c reserves the
     * selected range with memblock_reserve before using it.
     */
    symbol->memblock_phys_alloc_relo = get_symbol_offset_zero(kallsym, img_buf, "memblock_find_in_range");
    if (symbol->memblock_phys_alloc_relo) {
        symbol->memblock_phys_alloc_type = MAP_SYM_MEMBLOCK_FIND_IN_RANGE;
    } else {
        symbol->memblock_phys_alloc_relo =
            get_symbol_offset_zero(kallsym, img_buf, "memblock_phys_alloc_try_nid");
        if (symbol->memblock_phys_alloc_relo) {
            symbol->memblock_phys_alloc_type = MAP_SYM_MEMBLOCK_PHYS_ALLOC_TRY_NID;
        }
    }

    /*
     * The nopanic variant has the same five-argument ABI but lets the map
     * probe handle an unavailable range without entering the kernel panic
     * path. Fall back to the regular variant only on kernels lacking it.
     */
    symbol->memblock_virt_alloc_relo =
        get_symbol_offset_zero(kallsym, img_buf, "memblock_virt_alloc_try_nid_nopanic");
    if (!symbol->memblock_virt_alloc_relo) {
        symbol->memblock_virt_alloc_relo =
            get_symbol_offset_zero(kallsym, img_buf, "memblock_virt_alloc_try_nid");
    }
    if (symbol->memblock_virt_alloc_relo) {
        symbol->memblock_virt_alloc_type = MAP_SYM_MEMBLOCK_VIRT_ALLOC_TRY_NID;
    }

    if (!symbol->memblock_phys_alloc_relo) {
        tools_loge_exit("no verified physical allocator or memblock_find_in_range\\n");
    }
    if (!symbol->memblock_virt_alloc_relo) {
        tools_loge_exit("no verified five-argument memblock virtual allocator\\n");
    }
    if (symbol->memblock_phys_alloc_type == MAP_SYM_MEMBLOCK_FIND_IN_RANGE) {
        tools_logi("use memblock_find_in_range + memblock_reserve as map phys allocator\\n");
    }
    if (get_symbol_offset_zero(kallsym, img_buf, "memblock_virt_alloc_try_nid_nopanic") ==
        symbol->memblock_virt_alloc_relo) {
        tools_logi("use memblock_virt_alloc_try_nid_nopanic for map linear probe\\n");
    }

    if ((is_be() ^ target_is_be)) {
        for (int64_t *pos = (int64_t *)symbol; pos < (int64_t *)((char *)symbol + sizeof(*symbol)); pos++) {
            *pos = i64swp(*pos);
        }
    }
    return 0;
}

static int get_cand_arr_symbol_offset_zero(kallsym_t *kallsym, char *img_buf, char **cand_arr, int cand_num)
{
    int offset = 0;
    for (int i = 0; i < cand_num; i++) {
        offset = get_symbol_offset_zero(kallsym, img_buf, cand_arr[i]);
        if (offset) break;
    }
    return offset;
}

/*
 * Resolve the local kernel_init entry that is passed to kernel_thread from
 * rest_init. CONFIG_KALLSYMS_ALL=n can omit this static function from the
 * symbol table. On the Y73S 4.14.141 image, the function pointer is loaded
 * with ADRP+ADD, points at a CFI branch stub, and that stub branches back into
 * rest_init's symbol extent. Only accept a unique in-image target in that
 * extent; otherwise fail closed and leave kernel-init KPM events unavailable.
 */
static int32_t resolve_kernel_init_from_rest_init(kallsym_t *kallsym, char *img_buf, int imglen,
                                                   int32_t target_is_be)
{
    int32_t rest_init_size = 0;
    int32_t rest_init_offset;
    int32_t kernel_thread_offset;
    int64_t rest_init_end;
    int32_t resolved = 0;

    if (!kallsym || !img_buf || imglen <= 0 || kallsym->arch != ARM64) return 0;

    rest_init_offset = get_symbol_offset_and_size(kallsym, img_buf, "rest_init", &rest_init_size);
    if (rest_init_offset <= 0 || rest_init_size <= 0 ||
        (int64_t)rest_init_offset + rest_init_size > imglen) return 0;

    kernel_thread_offset = try_get_symbol_offset_zero(kallsym, img_buf, "kernel_thread.cfi");
    if (!kernel_thread_offset) {
        kernel_thread_offset = try_get_symbol_offset_zero(kallsym, img_buf, "kernel_thread");
    }
    if (kernel_thread_offset <= 0) return 0;

    rest_init_end = (int64_t)rest_init_offset + rest_init_size;
    for (int32_t pc = rest_init_offset; (int64_t)pc + 4 <= rest_init_end; pc += 4) {
        uint32_t call_insn = (uint32_t)uint_unpack(img_buf + pc, 4, target_is_be);
        uint32_t adrp_insn;
        uint32_t add_insn;
        uint32_t stub_insn;
        int64_t call_target;
        int64_t page;
        int64_t stub_offset;
        int64_t body_offset;
        uint64_t add_imm;

        if (!aarch64_insn_is_bl(call_insn)) continue;
        call_target = (int64_t)pc + aarch64_get_branch_offset(call_insn);
        if (call_target != kernel_thread_offset || pc < 8) continue;

        /*
         * The Y73S compiler places two unrelated argument setup instructions
         * (ORR w2, MOV x1) between ADRP/ADD x0 and BL kernel_thread. Search a
         * short bounded window for ADD x0,x0,#imm, and accept only known
         * x0-preserving instructions between that ADD and the call.
         */
        int found_x0_pair = 0;
        for (int32_t add_pc = pc - 4; add_pc >= pc - 16 && add_pc >= rest_init_offset + 4;
             add_pc -= 4) {
            int preserves_x0 = 1;
            for (int32_t mid_pc = add_pc + 4; mid_pc < pc; mid_pc += 4) {
                uint32_t mid_insn = (uint32_t)uint_unpack(img_buf + mid_pc, 4, target_is_be);
                if ((!aarch64_insn_is_orr_imm(mid_insn) && !aarch64_insn_is_orr(mid_insn)) ||
                    aarch64_insn_decode_register(AARCH64_INSN_REGTYPE_RD, mid_insn) == AARCH64_INSN_REG_0) {
                    preserves_x0 = 0;
                    break;
                }
            }
            if (!preserves_x0) continue;

            add_insn = (uint32_t)uint_unpack(img_buf + add_pc, 4, target_is_be);
            if (!aarch64_insn_is_add_imm(add_insn) || !(add_insn & 0x80000000U) ||
                aarch64_insn_decode_register(AARCH64_INSN_REGTYPE_RD, add_insn) != AARCH64_INSN_REG_0 ||
                aarch64_insn_decode_register(AARCH64_INSN_REGTYPE_RN, add_insn) != AARCH64_INSN_REG_0) {
                continue;
            }

            int32_t adrp_pc = add_pc - 4;
            adrp_insn = (uint32_t)uint_unpack(img_buf + adrp_pc, 4, target_is_be);
            if (!aarch64_insn_is_adrp(adrp_insn) ||
                aarch64_insn_decode_register(AARCH64_INSN_REGTYPE_RD, adrp_insn) != AARCH64_INSN_REG_0) {
                continue;
            }

            page = ((int64_t)adrp_pc) & ~((int64_t)0xfff);
            page += aarch64_insn_adrp_get_offset(adrp_insn);
            found_x0_pair = 1;
            break;
        }
        if (!found_x0_pair) continue;
        add_imm = aarch64_insn_decode_immediate(AARCH64_INSN_IMM_12, add_insn);
        if ((add_insn >> 22) & 1) add_imm <<= 12;
        stub_offset = page + (int64_t)add_imm;
        /* A function-pointer CFI target must be an aligned in-image stub. */
        if (stub_offset < 0 || (stub_offset & 3) || stub_offset + 4 > imglen) continue;

        stub_insn = (uint32_t)uint_unpack(img_buf + stub_offset, 4, target_is_be);
        /* Do not treat an arbitrary instruction inside rest_init as a function
         * entry: Y73S uses a CFI B veneer which branches to the local body. */
        if (!aarch64_insn_is_b(stub_insn)) continue;
        body_offset = stub_offset + aarch64_get_branch_offset(stub_insn);

        /* The Y73S local kernel_init body is embedded in rest_init's
         * KALLSYMS size range; kthreadd's CFI stub branches outside it. */
        if (body_offset < 0 || (body_offset & 3) ||
            body_offset <= rest_init_offset || body_offset >= rest_init_end ||
            body_offset + 4 > rest_init_end || body_offset + 4 > imglen) continue;

        if (resolved && resolved != body_offset) return 0;
        resolved = (int32_t)body_offset;
    }

    return resolved;
}


/*
 * Y73S V2031A / PD2031, Android 10, Linux 4.14.141+ (2022-02-15 build).
 * avc_denied is a local static function and is omitted from KALLSYMS_ALL=n.
 * Accept this one image-specific fallback only when the complete entry
 * fingerprint and its in-image caller BL both match. Never generalize the
 * offset to other 4.14 kernels or firmware builds.
 */
static int32_t resolve_y73s_avc_denied_fingerprint(kallsym_t *kallsym, char *img_buf,
                                                    int imglen, int32_t target_is_be)
{
    static const uint32_t expected[] = {
        0x37000166, 0xb000ce6b, 0xb948ad6b, 0x2a0203ea,
        0x2a0103e8, 0x2a0003e9, 0x340000eb, 0x394040eb,
        0x370000ab, 0x321c77e0, 0xd65f03c0, 0x321c77e0,
        0xd65f03c0, 0xd10083ff, 0xa9017bfd, 0x910043fd,
        0xb9400ce7, 0xb9000be6, 0x320003e0, 0x2a0303e1,
        0x2a0403e2, 0x2a0503e3, 0x2a0903e4, 0x2a0803e5,
        0x2a0a03e6, 0xf90003ff, 0x97fffecb, 0xa9417bfd,
        0x2a1f03e0, 0x910083ff, 0xd65f03c0
    };
    const int32_t function_offset = 0x0069141c;
    const int32_t caller_offset = 0x00691d74;

    if (!kallsym || !img_buf || kallsym->arch != ARM64 ||
        kallsym->version.major != 4 || kallsym->version.minor != 14 ||
        kallsym->version.patch != 141 || target_is_be ||
        imglen != 47517708 || imglen < 4 ||
        function_offset > imglen - (int32_t)sizeof(expected) ||
        caller_offset > imglen - 4) {
        return 0;
    }

    for (size_t i = 0; i < ARRAY_SIZE(expected); i++) {
        uint32_t word = (uint32_t)uint_unpack(img_buf + function_offset + i * 4, 4, target_is_be);
        if (word != expected[i]) return 0;
    }

    uint32_t caller = (uint32_t)uint_unpack(img_buf + caller_offset, 4, target_is_be);
    if (!aarch64_insn_is_bl(caller)) return 0;
    if ((int64_t)caller_offset + aarch64_get_branch_offset(caller) != function_offset) return 0;

    return function_offset;
}

int fillin_patch_config(kallsym_t *kallsym, char *img_buf, int imglen, patch_config_t *symbol, int32_t target_is_be,
                        bool is_android)
{
    symbol->kallsyms_lookup_name = get_usable_symbol_offset_try(kallsym, img_buf, imglen, "kallsyms_lookup_name");
    symbol->printk = get_symbol_offset_zero(kallsym, img_buf, "printk");
    if (!symbol->printk) symbol->printk = get_symbol_offset_zero(kallsym, img_buf, "_printk");
    if (!symbol->printk) tools_loge_exit("no symbol printk");

    symbol->panic = get_symbol_offset_zero(kallsym, img_buf, "panic");
    // panic exists on every kernel; without it the KP core cannot attach its
    // bootlog dump and a patched image that misses it is almost always broken
    if (!symbol->panic) tools_loge_exit("no symbol panic (KP core cannot hook panic, patch aborted)");

    symbol->rest_init = try_get_symbol_offset_zero(kallsym, img_buf, "rest_init");
    if (!symbol->rest_init) symbol->cgroup_init = try_get_symbol_offset_zero(kallsym, img_buf, "cgroup_init");
    if (!symbol->rest_init && !symbol->cgroup_init) tools_loge_exit("no symbol rest_init");

    symbol->kernel_init = try_get_symbol_offset_zero(kallsym, img_buf, "kernel_init");
    if (!symbol->kernel_init && symbol->rest_init) {
        symbol->kernel_init = resolve_kernel_init_from_rest_init(kallsym, img_buf, imglen, target_is_be);
        if (symbol->kernel_init) {
            tools_logi("kernel_init resolved from rest_init kernel_thread callsite: 0x%08x\n",
                       (unsigned int)symbol->kernel_init);
        }
    }
    if (!symbol->kernel_init) {
        tools_logw("no symbol kernel_init (rest_init callsite resolution failed; PRE/POST_KERNEL_INIT events unavailable)\n");
    }

    symbol->report_cfi_failure = get_symbol_offset_zero(kallsym, img_buf, "report_cfi_failure");
    symbol->__cfi_slowpath_diag = get_symbol_offset_zero(kallsym, img_buf, "__cfi_slowpath_diag");
    symbol->__cfi_slowpath = get_symbol_offset_zero(kallsym, img_buf, "__cfi_slowpath");
    if (!symbol->report_cfi_failure && !symbol->__cfi_slowpath_diag && !symbol->__cfi_slowpath) {
        tools_logw("no CFI failure handler symbol (report_cfi_failure / __cfi_slowpath_diag / __cfi_slowpath)\n");
        tools_logw("if the kernel has CONFIG_CFI_CLANG (Android 13+ GKI common), every kCFI mismatch on KP memory will panic -> random reboots; the KP core will retry resolution via kallsyms at boot\n");
    }

    symbol->copy_process = try_get_symbol_offset_zero(kallsym, img_buf, "copy_process");
    if (!symbol->copy_process) symbol->cgroup_post_fork = get_symbol_offset_zero(kallsym, img_buf, "cgroup_post_fork");
    if (!symbol->copy_process && !symbol->cgroup_post_fork) tools_loge_exit("no symbol copy_process");

    //  gcc -fipa-sra eg: avc_denied.isra.5
    symbol->avc_denied = try_get_symbol_offset_zero(kallsym, img_buf, "avc_denied");
    if (!symbol->avc_denied) {
        symbol->avc_denied = resolve_y73s_avc_denied_fingerprint(kallsym, img_buf, imglen, target_is_be);
        if (symbol->avc_denied) {
            tools_logi("vivo Y73s 4.14.141 avc_denied fingerprint verified: 0x%08x\n",
                       (unsigned int)symbol->avc_denied);
        }
    }
    if (!symbol->avc_denied && is_android) tools_loge_exit("no symbol avc_denied");

    symbol->slow_avc_audit = try_get_symbol_offset_zero(kallsym, img_buf, "slow_avc_audit");

    symbol->input_handle_event = try_get_symbol_offset_zero(kallsym, img_buf, "input_handle_event");

    if ((is_be() ^ target_is_be)) {
        for (int64_t *pos = (int64_t *)symbol; pos <= (int64_t *)symbol; pos++) {
            *pos = i64swp(*pos);
        }
    }
    return 0;
}
