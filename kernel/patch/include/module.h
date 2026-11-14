/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#ifndef _KP_MODULE_H_
#define _KP_MODULE_H_

#include <asm-generic/module.h>
#include <kpmodule.h>

struct load_info
{
    struct
    {
        const char *base;
        unsigned long size;
        const char *name, *version, *license, *author, *description;
        char error_msg[KPM_LOAD_ERROR_MESSAGE_LEN];
    } info;
    const Elf_Ehdr *hdr;
    unsigned long len;
    Elf_Shdr *sechdrs;
    char *secstrings, *strtab;
    unsigned long symoffs, stroffs;
    struct
    {
        unsigned int sym, str, mod, info;
    } index;
};

enum kp_module_state {
    KP_MODULE_LOADING = 0,
    KP_MODULE_LIVE,
    KP_MODULE_UNLOADING,
    KP_MODULE_EXITING,
    KP_MODULE_DEAD,
};

struct module
{
    /* Protected by module_lock. Hook registrations pin the image until
     * their chain slots are retired and all in-flight dispatches drain. */
    enum kp_module_state state;
    unsigned int active_calls;
    unsigned int hook_refs;
    bool exit_called;

    struct
    {
        const char *base, *name, *version, *license, *author, *description;
    } info;

    char *args;
    char load_event[32];
    char load_source[16];

    mod_initcall_t *init;
    mod_ctl0call_t *ctl0;
    mod_ctl1call_t *ctl1;
    mod_exitcall_t *exit;
    mod_eventcall_t *event;

    unsigned int size;
    unsigned int text_size;
    unsigned int ro_size;
    unsigned int symtab_start;

    void *start;

    struct list_head list;
};

long load_module(const void *data, int len, const char *args, const char *event, void *__user reserved);
long load_module_ex(const void *data, int len, const char *args, const char *event, const char *source,
                    void *__user reserved);
long load_module_path(const char *path, const char *args, void *__user reserved);
long load_module_path_event(const char *path, const char *args, const char *event, void *__user reserved);
long module_control0(const char *name, const char *ctl_args, char *__user out_msg, int outlen);
long module_control1(const char *name, void *a1, void *a2, void *a3);
long unload_module(const char *name, void *__user reserved);
long notify_modules_event(const char *event, const char *args, void *__user reserved);

int get_module_nums();
int list_modules(char *out_names, int size);
int get_module_info(const char *name, char *out_info, int size);

/* Hook engine ownership protocol. A successful registration returns an
 * opaque module token (NULL means kernel-resident callback). */
int kp_hook_owner_register(unsigned long addr, void **owner);
void kp_hook_owner_unregister(void *owner);
int kp_hook_owner_call_get(void *owner);
void kp_hook_owner_call_put(void *owner);
int kp_kpm_owner_pin(unsigned long callback_addr, void **owner);
void kp_kpm_owner_unpin(void *owner);
int kp_kpm_owner_call_get(void *owner);
void kp_kpm_owner_call_put(void *owner);

#endif
