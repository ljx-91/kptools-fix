/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 */

#include "symbol.h"
#include "common.h"

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
    if (!symbol->kernel_init) tools_logw("no symbol kernel_init (KPM event timing degraded)\n");

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
