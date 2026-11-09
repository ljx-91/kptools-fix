// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 *
 * Ported from kernel/patch/module/relo.c. Applies AArch64 RELA relocations to
 * a loaded KPM image. The encoder comes from insn.c.
 */
#include "insn.h"
#include "module.h"

#include <linux/elf.h>
#include <linux/errno.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/vmalloc.h>

enum kp_aarch64_reloc_op {
	RELOC_OP_NONE,
	RELOC_OP_ABS,
	RELOC_OP_PREL,
	RELOC_OP_PAGE,
};

static u64 do_reloc(enum kp_aarch64_reloc_op reloc_op, void *place, u64 val)
{
	switch (reloc_op) {
	case RELOC_OP_ABS:
		return val;
	case RELOC_OP_PREL:
		return val - (u64)place;
	case RELOC_OP_PAGE:
		return (val & ~0xfff) - ((u64)place & ~0xfff);
	case RELOC_OP_NONE:
		return 0;
	}

	pr_err("do_reloc: unknown relocation operation %d\n", reloc_op);
	return 0;
}

static int reloc_data(enum kp_aarch64_reloc_op op, void *place, u64 val, int len)
{
	u64 imm_mask;
	s64 sval = do_reloc(op, place, val);
	s64 value = sval;

	if (len == 64)
		imm_mask = ~0ULL;
	else if (len == 16 || len == 32)
		imm_mask = (1ULL << len) - 1;
	else {
		pr_err("Invalid length (%d) for data relocation\n", len);
		return -EINVAL;
	}
	/* PREL relocations encode a signed displacement. ABS relocations
	 * permit either a signed or unsigned narrow value per AAELF64. */
	if (op == RELOC_OP_PREL && len < 64) {
		if (value < -(1LL << (len - 1)) ||
		    value >= (1LL << (len - 1)))
			return -ERANGE;
	} else {
		/* ABS overflow range: -2^(n-1) <= X < 2^n. */
		sval = (s64)(sval & ~(imm_mask >> 1)) >> (len - 1);
		if ((u64)(sval + 1) > 2)
			return -ERANGE;
	}

	switch (len) {
	case 16: {
		s16 encoded = (s16)value;
		memcpy(place, &encoded, sizeof(encoded));
		break;
	}
	case 32: {
		s32 encoded = (s32)value;
		memcpy(place, &encoded, sizeof(encoded));
		break;
	}
	case 64: {
		s64 encoded = value;
		memcpy(place, &encoded, sizeof(encoded));
		break;
	}
	default:
		return -EINVAL;
	}


	return 0;
}

static int reloc_insn_movw(enum kp_aarch64_reloc_op op, void *place, u64 val, int lsb,
			   enum kp_aarch64_insn_imm_type imm_type)
{
	u64 imm, limit = 0;
	s64 sval;
	u32 insn = *(u32 *)place;

	sval = do_reloc(op, place, val);
	sval >>= lsb;
	imm = sval & 0xffff;

	if (imm_type == KP_AARCH64_INSN_IMM_MOVNZ) {
		/* For signed MOVW relocations, manipulate the instruction
		 * encoding depending on whether the immediate is negative. */
		insn &= ~(3 << 29);
		if ((s64)imm >= 0) {
			/* >=0: MOVZ (opcode 10b). */
			insn |= 2 << 29;
		} else {
			/* <0: MOVN (opcode 00b), invert the immediate. */
			imm = ~imm;
		}
		imm_type = KP_AARCH64_INSN_IMM_MOVK;
	}

	insn = kp_aarch64_insn_encode_immediate(imm_type, insn, imm);
	*(u32 *)place = insn;

	sval >>= 16;

	/* For unsigned immediates, the sign bit is past the most significant
	 * bit of the field; AARCH64_INSN_IMM_16 is unsigned. */
	if (imm_type != KP_INSN_IMM_16) {
		sval++;
		limit++;
	}

	if ((u64)sval > limit)
		return -ERANGE;

	return 0;
}

static int reloc_insn_imm(enum kp_aarch64_reloc_op op, void *place, u64 val, int lsb, int len,
			  enum kp_aarch64_insn_imm_type imm_type)
{
	u64 imm, imm_mask;
	s64 sval;
	u32 insn = *(u32 *)place;

	sval = do_reloc(op, place, val);
	sval >>= lsb;
	imm_mask = (BIT(lsb + len) - 1) >> lsb;
	imm = sval & imm_mask;
	insn = kp_aarch64_insn_encode_immediate(imm_type, insn, imm);
	*(u32 *)place = insn;

	sval = (s64)(sval & ~(imm_mask >> 1)) >> (len - 1);
	if ((u64)(sval + 1) >= 2)
		return -ERANGE;

	return 0;
}

int kp_apply_relocate(Elf64_Shdr *sechdrs, const char *strtab, unsigned int symindex,
		      unsigned int relsec, struct kp_module *me)
{
	/* AArch64 KPMs are expected to use RELA. Never report unapplied REL as success. */
	return -EOPNOTSUPP;
}

static unsigned int kp_reloc_write_width(unsigned int type)
{
	switch (type) {
	case R_AARCH64_NONE:
	case R_ARM_NONE:
		return 0;
	case R_AARCH64_ABS16:
	case R_AARCH64_PREL16:
		return 2;
	case R_AARCH64_ABS32:
	case R_AARCH64_PREL32:
		return 4;
	case R_AARCH64_ABS64:
	case R_AARCH64_PREL64:
		return 8;
	default:
		/* All supported instruction relocations patch one A64 instruction. */
		return 4;
	}
}

int kp_apply_relocate_add(Elf64_Shdr *sechdrs, const char *strtab, unsigned int symindex,
			  unsigned int relsec, struct kp_module *me)
{
	unsigned int i, nrel, nsym;
	Elf64_Shdr *rsec, *target, *symsec;
	Elf64_Sym *sym;
	Elf64_Rela *rel;
	void *loc;
	u64 val;
	int ovf;
	bool overflow_check;
	void *backup;
	int ret;

	(void)strtab;
	(void)me;
	if (!sechdrs || !symindex || !relsec)
		return -EINVAL;
	rsec = &sechdrs[relsec];
	if (rsec->sh_type != SHT_RELA || rsec->sh_entsize != sizeof(Elf64_Rela) ||
	    rsec->sh_size % sizeof(Elf64_Rela))
		return -ENOEXEC;
	if (rsec->sh_info == 0 || rsec->sh_link != symindex)
		return -ENOEXEC;
	target = &sechdrs[rsec->sh_info];
	symsec = &sechdrs[symindex];
	/* layout_symtab() repurposes sh_entsize as the in-image offset
	 * after setup_load_info() has validated the original ELF entry size.
	 * Do not interpret that private offset as ELF metadata here. */
	if (!(target->sh_flags & SHF_ALLOC) || !target->sh_addr ||
	    symsec->sh_type != SHT_SYMTAB ||
	    symsec->sh_size % sizeof(Elf64_Sym) || !symsec->sh_addr)
		return -ENOEXEC;

	nrel = rsec->sh_size / sizeof(Elf64_Rela);
	nsym = symsec->sh_size / sizeof(Elf64_Sym);
	rel = (Elf64_Rela *)rsec->sh_addr;

	/* Validate every record before the first write. */
	for (i = 0; i < nrel; i++) {
		unsigned int type = ELF64_R_TYPE(rel[i].r_info);
		unsigned int symidx = ELF64_R_SYM(rel[i].r_info);
		unsigned int width = kp_reloc_write_width(type);

		if (symidx >= nsym)
			return -ENOEXEC;
		if (!width)
			continue;
		if (rel[i].r_offset > target->sh_size ||
		    width > target->sh_size - rel[i].r_offset)
			return -ENOEXEC;
		/* AArch64 instruction relocations patch a 32-bit instruction and
		 * require instruction alignment. Data relocations may target packed
		 * or otherwise byte-aligned objects; reloc_data() uses memcpy for them. */
		if (width == 4 && type != R_AARCH64_ABS32 &&
		    type != R_AARCH64_PREL32 &&
		    (((unsigned long)target->sh_addr + rel[i].r_offset) & 3))
			return -ENOEXEC;
	}

	backup = vmalloc(target->sh_size ? target->sh_size : 1);
	if (!backup)
		return -ENOMEM;
	if (target->sh_size)
		memcpy(backup, (void *)target->sh_addr, target->sh_size);

	for (i = 0; i < nrel; i++) {
		unsigned int type = ELF64_R_TYPE(rel[i].r_info);
		loc = (void *)target->sh_addr + rel[i].r_offset;
		sym = (Elf64_Sym *)symsec->sh_addr + ELF64_R_SYM(rel[i].r_info);
		val = sym->st_value + rel[i].r_addend;
		overflow_check = true;

		switch (type) {
		case R_ARM_NONE:
		case R_AARCH64_NONE:
			ovf = 0;
			break;
		case R_AARCH64_ABS64:
			overflow_check = false;
			ovf = reloc_data(RELOC_OP_ABS, loc, val, 64);
			break;
		case R_AARCH64_ABS32:
			ovf = reloc_data(RELOC_OP_ABS, loc, val, 32);
			break;
		case R_AARCH64_ABS16:
			ovf = reloc_data(RELOC_OP_ABS, loc, val, 16);
			break;
		case R_AARCH64_PREL64:
			overflow_check = false;
			ovf = reloc_data(RELOC_OP_PREL, loc, val, 64);
			break;
		case R_AARCH64_PREL32:
			ovf = reloc_data(RELOC_OP_PREL, loc, val, 32);
			break;
		case R_AARCH64_PREL16:
			ovf = reloc_data(RELOC_OP_PREL, loc, val, 16);
			break;
		case R_AARCH64_MOVW_UABS_G0_NC: overflow_check = false; fallthrough;
		case R_AARCH64_MOVW_UABS_G0: ovf = reloc_insn_movw(RELOC_OP_ABS, loc, val, 0, KP_INSN_IMM_16); break;
		case R_AARCH64_MOVW_UABS_G1_NC: overflow_check = false; fallthrough;
		case R_AARCH64_MOVW_UABS_G1: ovf = reloc_insn_movw(RELOC_OP_ABS, loc, val, 16, KP_INSN_IMM_16); break;
		case R_AARCH64_MOVW_UABS_G2_NC: overflow_check = false; fallthrough;
		case R_AARCH64_MOVW_UABS_G2: ovf = reloc_insn_movw(RELOC_OP_ABS, loc, val, 32, KP_INSN_IMM_16); break;
		case R_AARCH64_MOVW_UABS_G3: overflow_check = false; ovf = reloc_insn_movw(RELOC_OP_ABS, loc, val, 48, KP_INSN_IMM_16); break;
		case R_AARCH64_MOVW_SABS_G0: ovf = reloc_insn_movw(RELOC_OP_ABS, loc, val, 0, KP_AARCH64_INSN_IMM_MOVNZ); break;
		case R_AARCH64_MOVW_SABS_G1: ovf = reloc_insn_movw(RELOC_OP_ABS, loc, val, 16, KP_AARCH64_INSN_IMM_MOVNZ); break;
		case R_AARCH64_MOVW_SABS_G2: ovf = reloc_insn_movw(RELOC_OP_ABS, loc, val, 32, KP_AARCH64_INSN_IMM_MOVNZ); break;
		case R_AARCH64_MOVW_PREL_G0_NC: overflow_check = false; fallthrough;
		case R_AARCH64_MOVW_PREL_G0: ovf = reloc_insn_movw(RELOC_OP_PREL, loc, val, 0, KP_AARCH64_INSN_IMM_MOVK); break;
		case R_AARCH64_MOVW_PREL_G1_NC: overflow_check = false; fallthrough;
		case R_AARCH64_MOVW_PREL_G1: ovf = reloc_insn_movw(RELOC_OP_PREL, loc, val, 16, KP_AARCH64_INSN_IMM_MOVK); break;
		case R_AARCH64_MOVW_PREL_G2_NC: overflow_check = false; fallthrough;
		case R_AARCH64_MOVW_PREL_G2: ovf = reloc_insn_movw(RELOC_OP_PREL, loc, val, 32, KP_AARCH64_INSN_IMM_MOVK); break;
		case R_AARCH64_MOVW_PREL_G3: overflow_check = false; ovf = reloc_insn_movw(RELOC_OP_PREL, loc, val, 48, KP_AARCH64_INSN_IMM_MOVNZ); break;
		case R_AARCH64_LD_PREL_LO19: ovf = reloc_insn_imm(RELOC_OP_PREL, loc, val, 2, 19, KP_INSN_IMM_19); break;
		case R_AARCH64_ADR_PREL_LO21: ovf = reloc_insn_imm(RELOC_OP_PREL, loc, val, 0, 21, KP_INSN_IMM_ADR); break;
		case R_AARCH64_ADR_PREL_PG_HI21_NC: overflow_check = false; fallthrough;
		case R_AARCH64_ADR_PREL_PG_HI21: ovf = reloc_insn_imm(RELOC_OP_PAGE, loc, val, 12, 21, KP_INSN_IMM_ADR); break;
		case R_AARCH64_ADD_ABS_LO12_NC:
		case R_AARCH64_LDST8_ABS_LO12_NC: overflow_check = false; ovf = reloc_insn_imm(RELOC_OP_ABS, loc, val, 0, 12, KP_INSN_IMM_12); break;
		case R_AARCH64_LDST16_ABS_LO12_NC: overflow_check = false; ovf = reloc_insn_imm(RELOC_OP_ABS, loc, val, 1, 11, KP_INSN_IMM_12); break;
		case R_AARCH64_LDST32_ABS_LO12_NC: overflow_check = false; ovf = reloc_insn_imm(RELOC_OP_ABS, loc, val, 2, 10, KP_INSN_IMM_12); break;
		case R_AARCH64_LDST64_ABS_LO12_NC: overflow_check = false; ovf = reloc_insn_imm(RELOC_OP_ABS, loc, val, 3, 9, KP_INSN_IMM_12); break;
		case R_AARCH64_LDST128_ABS_LO12_NC: overflow_check = false; ovf = reloc_insn_imm(RELOC_OP_ABS, loc, val, 4, 8, KP_INSN_IMM_12); break;
		case R_AARCH64_TSTBR14: ovf = reloc_insn_imm(RELOC_OP_PREL, loc, val, 2, 14, KP_INSN_IMM_14); break;
		case R_AARCH64_CONDBR19: ovf = reloc_insn_imm(RELOC_OP_PREL, loc, val, 2, 19, KP_INSN_IMM_19); break;
		case R_AARCH64_JUMP26:
		case R_AARCH64_CALL26: ovf = reloc_insn_imm(RELOC_OP_PREL, loc, val, 2, 26, KP_INSN_IMM_26); break;
		default:
			pr_err("unsupported RELA relocation: %u\\n", type);
			ret = -ENOEXEC;
			goto rollback;
		}
		if (ovf == -ERANGE && !overflow_check)
			ovf = 0; /* *_NC relocations intentionally truncate the checked field. */
		if (overflow_check && ovf == -ERANGE) {
			pr_err("overflow in relocation type %u val %llx\\n", type, val);
			ret = -ENOEXEC;
			goto rollback;
		}
		if (ovf < 0) {
			ret = ovf;
			goto rollback;
		}
	}
	vfree(backup);
	return 0;

rollback:
	if (target->sh_size)
		memcpy((void *)target->sh_addr, backup, target->sh_size);
	vfree(backup);
	return ret;
}
