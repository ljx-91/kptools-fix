#include <linux/printk.h>
#include <linux/elf.h>
#include <uapi/linux/elf.h>
#include <asm/elf.h>
#include <kpmalloc.h>
#include <linux/err.h>
#include <linux/vmalloc.h>
#include <linux/string.h>

#include "insn.h"

#define AARCH64_INSN_IMM_MOVNZ AARCH64_INSN_IMM_MAX
#define AARCH64_INSN_IMM_MOVK AARCH64_INSN_IMM_16

#define le32_to_cpu(x) (x)
#define cpu_to_le32(x) (x)

enum aarch64_reloc_op
{
    RELOC_OP_NONE,
    RELOC_OP_ABS,
    RELOC_OP_PREL,
    RELOC_OP_PAGE,
};

static u64 do_reloc(enum aarch64_reloc_op reloc_op, void *place, u64 val)
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

static int reloc_data(enum aarch64_reloc_op op, void *place, u64 val, int len)
{
    u64 imm_mask;
    s64 sval;

    if (len != 16 && len != 32 && len != 64) {
        pr_err("Invalid length (%d) for data relocation\\n", len);
        return -EINVAL;
    }

    /* Avoid undefined shifts, especially shifting a 32-bit int by 64. */
    imm_mask = len == 64 ? ~0ULL : ((1ULL << len) - 1);
    sval = do_reloc(op, place, val);

    /*
     * Check representability before modifying the destination. For 64-bit
     * relocations every bit is retained, so the signed-width check is moot.
     */
    if (len != 64) {
        s64 upper = (s64)(sval & ~(imm_mask >> 1)) >> (len - 1);
        if ((u64)(upper + 1) > 2) return -ERANGE;
    }

    switch (len) {
    case 16:
        *(s16 *)place = (s16)sval;
        break;
    case 32:
        *(s32 *)place = (s32)sval;
        break;
    case 64:
        *(s64 *)place = sval;
        break;
    }
    return 0;
}

static int reloc_insn_movw(enum aarch64_reloc_op op, void *place, u64 val, int lsb, enum aarch64_insn_imm_type imm_type)
{
    u64 imm, limit = 0;
    s64 sval;
    u32 insn = le32_to_cpu(*(u32 *)place);

    sval = do_reloc(op, place, val);
    sval >>= lsb;
    imm = sval & 0xffff;

    if (imm_type == AARCH64_INSN_IMM_MOVNZ) {
        /*
		 * For signed MOVW relocations, we have to manipulate the
		 * instruction encoding depending on whether or not the
		 * immediate is less than zero.
		 */
        insn &= ~(3 << 29);
        if ((s64)imm >= 0) {
            /* >=0: Set the instruction to MOVZ (opcode 10b). */
            insn |= 2 << 29;
        } else {
            /*
			 * <0: Set the instruction to MOVN (opcode 00b).
			 *     Since we've masked the opcode already, we
			 *     don't need to do anything other than
			 *     inverting the new immediate field.
			 */
            imm = ~imm;
        }
        imm_type = AARCH64_INSN_IMM_MOVK;
    }

    /* Prepare the instruction, but do not commit until overflow is checked. */
    insn = aarch64_insn_encode_immediate(imm_type, insn, imm);

    /* Shift out the immediate field. */
    sval >>= 16;

    /*
	 * For unsigned immediates, the overflow check is straightforward.
	 * For signed immediates, the sign bit is actually the bit past the
	 * most significant bit of the field.
	 * The AARCH64_INSN_IMM_16 immediate type is unsigned.
	 */
    if (imm_type != AARCH64_INSN_IMM_16) {
        sval++;
        limit++;
    }

    /* Check the upper bits depending on the sign of the immediate. */
    if ((u64)sval > limit) return -ERANGE;

    *(u32 *)place = cpu_to_le32(insn);
    return 0;
}

static int reloc_insn_imm(enum aarch64_reloc_op op, void *place, u64 val, int lsb, int len,
                          enum aarch64_insn_imm_type imm_type)
{
    u64 imm, imm_mask;
    s64 sval;
    u32 insn = le32_to_cpu(*(u32 *)place);

    /* Calculate the relocation value. */
    sval = do_reloc(op, place, val);
    sval >>= lsb;
    /* Extract the value bits and shift them to bit 0. */
    imm_mask = (BIT(lsb + len) - 1) >> lsb;
    imm = sval & imm_mask;
    /* Prepare the instruction's immediate field; commit after validation. */
    insn = aarch64_insn_encode_immediate(imm_type, insn, imm);
    /*
	 * Extract the upper value bits (including the sign bit) and
	 * shift them to bit 0.
	 */
    sval = (s64)(sval & ~(imm_mask >> 1)) >> (len - 1);
    /*
	 * Overflow has occurred if the upper bits are not all equal to
	 * the sign bit of the value.
	 */
    if ((u64)(sval + 1) >= 2) return -ERANGE;

    *(u32 *)place = cpu_to_le32(insn);
    return 0;
}

int apply_relocate(Elf64_Shdr *sechdrs, const char *strtab, unsigned int symindex, unsigned int relsec,
                   struct module *me)
{
    /* AArch64 REL relocations are not implemented by this loader. */
    return -ENOEXEC;
}

int apply_relocate_add(Elf64_Shdr *sechdrs, const char *strtab, unsigned int symindex, unsigned int relsec,
                       struct module *me)
{
    unsigned int i;
    int ovf, ret = 0;
    void *backup;
    bool overflow_check;
    Elf64_Sym *sym;
    void *loc;
    u64 val;
    Elf64_Shdr *relhdr, *targethdr, *symhdr;
    Elf64_Rela *rel;

    if (!sechdrs || relsec == 0 || symindex == 0) return -ENOEXEC;
    relhdr = &sechdrs[relsec];
    targethdr = &sechdrs[relhdr->sh_info];
    symhdr = &sechdrs[symindex];
    if (relhdr->sh_type != SHT_RELA || relhdr->sh_entsize != sizeof(Elf64_Rela) ||
        relhdr->sh_size % sizeof(Elf64_Rela) || relhdr->sh_link != symindex ||
        !relhdr->sh_addr || !(targethdr->sh_flags & SHF_ALLOC) || !targethdr->sh_addr ||
        symhdr->sh_type != SHT_SYMTAB || symhdr->sh_entsize != sizeof(Elf64_Sym) ||
        symhdr->sh_size % sizeof(Elf64_Sym) || !symhdr->sh_addr) return -ENOEXEC;
    rel = (void *)relhdr->sh_addr;

    /* Validate every target range and symbol index before any write. */
    for (i = 0; i < relhdr->sh_size / sizeof(*rel); i++) {
        unsigned int type = ELF64_R_TYPE(rel[i].r_info);
        unsigned int symno = ELF64_R_SYM(rel[i].r_info);
        unsigned int width;

        switch (type) {
        case R_ARM_NONE:
        case R_AARCH64_NONE: width = 0; break;
        case R_AARCH64_ABS64:
        case R_AARCH64_PREL64: width = 8; break;
        case R_AARCH64_ABS16:
        case R_AARCH64_PREL16: width = 2; break;
        default: width = 4; break;
        }
        if (symno >= symhdr->sh_size / sizeof(Elf64_Sym)) return -ENOEXEC;
        if (rel[i].r_offset > targethdr->sh_size ||
            width > targethdr->sh_size - rel[i].r_offset) return -ENOEXEC;
        if (width && (rel[i].r_offset & (width - 1))) return -ENOEXEC;
    }

    backup = vmalloc(targethdr->sh_size ? targethdr->sh_size : 1);
    if (!backup) return -ENOMEM;
    if (targethdr->sh_size)
        memcpy(backup, (void *)targethdr->sh_addr, targethdr->sh_size);

    for (i = 0; i < relhdr->sh_size / sizeof(*rel); i++) {
        unsigned int type = ELF64_R_TYPE(rel[i].r_info);
        unsigned int symno = ELF64_R_SYM(rel[i].r_info);
        unsigned int width;

        switch (type) {
        case R_ARM_NONE:
        case R_AARCH64_NONE: width = 0; break;
        case R_AARCH64_ABS64:
        case R_AARCH64_PREL64: width = 8; break;
        case R_AARCH64_ABS16:
        case R_AARCH64_PREL16: width = 2; break;
        default: width = 4; break;
        }
        if (symno >= symhdr->sh_size / sizeof(Elf64_Sym)) return -ENOEXEC;
        if (rel[i].r_offset > targethdr->sh_size ||
            width > targethdr->sh_size - rel[i].r_offset) return -ENOEXEC;
        if (width && (rel[i].r_offset & (width - 1))) return -ENOEXEC;

        /* loc corresponds to P in the AArch64 ELF document. */
        loc = (void *)targethdr->sh_addr + rel[i].r_offset;
        /* sym is the ELF symbol we're referring to. */
        sym = (Elf64_Sym *)symhdr->sh_addr + symno;
        /* val corresponds to (S + A) in the AArch64 ELF document. */
        val = sym->st_value + rel[i].r_addend;

        overflow_check = true;

        /* Perform the static relocation. */
        switch (ELF64_R_TYPE(rel[i].r_info)) {
        /* Null relocations. */
        case R_ARM_NONE:
        case R_AARCH64_NONE:
            ovf = 0;
            break;
        /* Data relocations. */
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

        /* MOVW instruction relocations. */
        case R_AARCH64_MOVW_UABS_G0_NC:
            overflow_check = false;
        case R_AARCH64_MOVW_UABS_G0:
            ovf = reloc_insn_movw(RELOC_OP_ABS, loc, val, 0, AARCH64_INSN_IMM_16);
            break;
        case R_AARCH64_MOVW_UABS_G1_NC:
            overflow_check = false;
        case R_AARCH64_MOVW_UABS_G1:
            ovf = reloc_insn_movw(RELOC_OP_ABS, loc, val, 16, AARCH64_INSN_IMM_16);
            break;
        case R_AARCH64_MOVW_UABS_G2_NC:
            overflow_check = false;
        case R_AARCH64_MOVW_UABS_G2:
            ovf = reloc_insn_movw(RELOC_OP_ABS, loc, val, 32, AARCH64_INSN_IMM_16);
            break;
        case R_AARCH64_MOVW_UABS_G3:
            /* We're using the top bits so we can't overflow. */
            overflow_check = false;
            ovf = reloc_insn_movw(RELOC_OP_ABS, loc, val, 48, AARCH64_INSN_IMM_16);
            break;
        case R_AARCH64_MOVW_SABS_G0:
            ovf = reloc_insn_movw(RELOC_OP_ABS, loc, val, 0, AARCH64_INSN_IMM_MOVNZ);
            break;
        case R_AARCH64_MOVW_SABS_G1:
            ovf = reloc_insn_movw(RELOC_OP_ABS, loc, val, 16, AARCH64_INSN_IMM_MOVNZ);
            break;
        case R_AARCH64_MOVW_SABS_G2:
            ovf = reloc_insn_movw(RELOC_OP_ABS, loc, val, 32, AARCH64_INSN_IMM_MOVNZ);
            break;
        case R_AARCH64_MOVW_PREL_G0_NC:
            overflow_check = false;
            ovf = reloc_insn_movw(RELOC_OP_PREL, loc, val, 0, AARCH64_INSN_IMM_MOVK);
            break;
        case R_AARCH64_MOVW_PREL_G0:
            ovf = reloc_insn_movw(RELOC_OP_PREL, loc, val, 0, AARCH64_INSN_IMM_MOVNZ);
            break;
        case R_AARCH64_MOVW_PREL_G1_NC:
            overflow_check = false;
            ovf = reloc_insn_movw(RELOC_OP_PREL, loc, val, 16, AARCH64_INSN_IMM_MOVK);
            break;
        case R_AARCH64_MOVW_PREL_G1:
            ovf = reloc_insn_movw(RELOC_OP_PREL, loc, val, 16, AARCH64_INSN_IMM_MOVNZ);
            break;
        case R_AARCH64_MOVW_PREL_G2_NC:
            overflow_check = false;
            ovf = reloc_insn_movw(RELOC_OP_PREL, loc, val, 32, AARCH64_INSN_IMM_MOVK);
            break;
        case R_AARCH64_MOVW_PREL_G2:
            ovf = reloc_insn_movw(RELOC_OP_PREL, loc, val, 32, AARCH64_INSN_IMM_MOVNZ);
            break;
        case R_AARCH64_MOVW_PREL_G3:
            /* We're using the top bits so we can't overflow. */
            overflow_check = false;
            ovf = reloc_insn_movw(RELOC_OP_PREL, loc, val, 48, AARCH64_INSN_IMM_MOVNZ);
            break;
        /* Immediate instruction relocations. */
        case R_AARCH64_LD_PREL_LO19:
            ovf = reloc_insn_imm(RELOC_OP_PREL, loc, val, 2, 19, AARCH64_INSN_IMM_19);
            break;
        case R_AARCH64_ADR_PREL_LO21:
            ovf = reloc_insn_imm(RELOC_OP_PREL, loc, val, 0, 21, AARCH64_INSN_IMM_ADR);
            break;
        case R_AARCH64_ADR_PREL_PG_HI21_NC:
            overflow_check = false;
        case R_AARCH64_ADR_PREL_PG_HI21:
            ovf = reloc_insn_imm(RELOC_OP_PAGE, loc, val, 12, 21, AARCH64_INSN_IMM_ADR);
            break;
        case R_AARCH64_ADD_ABS_LO12_NC:
        case R_AARCH64_LDST8_ABS_LO12_NC:
            overflow_check = false;
            ovf = reloc_insn_imm(RELOC_OP_ABS, loc, val, 0, 12, AARCH64_INSN_IMM_12);
            break;
        case R_AARCH64_LDST16_ABS_LO12_NC:
            overflow_check = false;
            ovf = reloc_insn_imm(RELOC_OP_ABS, loc, val, 1, 11, AARCH64_INSN_IMM_12);
            break;
        case R_AARCH64_LDST32_ABS_LO12_NC:
            overflow_check = false;
            ovf = reloc_insn_imm(RELOC_OP_ABS, loc, val, 2, 10, AARCH64_INSN_IMM_12);
            break;
        case R_AARCH64_LDST64_ABS_LO12_NC:
            overflow_check = false;
            ovf = reloc_insn_imm(RELOC_OP_ABS, loc, val, 3, 9, AARCH64_INSN_IMM_12);
            break;
        case R_AARCH64_LDST128_ABS_LO12_NC:
            overflow_check = false;
            ovf = reloc_insn_imm(RELOC_OP_ABS, loc, val, 4, 8, AARCH64_INSN_IMM_12);
            break;
        case R_AARCH64_TSTBR14:
            ovf = reloc_insn_imm(RELOC_OP_PREL, loc, val, 2, 14, AARCH64_INSN_IMM_14);
            break;
        case R_AARCH64_CONDBR19:
            ovf = reloc_insn_imm(RELOC_OP_PREL, loc, val, 2, 19, AARCH64_INSN_IMM_19);
            break;
        case R_AARCH64_JUMP26:
        case R_AARCH64_CALL26:
            ovf = reloc_insn_imm(RELOC_OP_PREL, loc, val, 2, 26, AARCH64_INSN_IMM_26);
            break;
        default:
            pr_err("unsupported RELA relocation: %llu\n", ELF64_R_TYPE(rel[i].r_info));
            ret = -ENOEXEC;
            goto rollback;
        }

        if (overflow_check && ovf == -ERANGE) goto overflow;
    }
    vfree(backup);
    return 0;

rollback:
    if (targethdr->sh_size)
        memcpy((void *)targethdr->sh_addr, backup, targethdr->sh_size);
    vfree(backup);
    return ret;
}