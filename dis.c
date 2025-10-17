#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "i286dis.h"

const char *reg_mnemonics[] = {
	"al",
	"ah",
	"bl",
	"bh",
	"cl",
	"ch",
	"dl",
	"dh",
	"ax",
	"bx",
	"cx",
	"dx",
	"sp",
	"bp",
	"si",
	"di",
};

const char *seg_mnemonics[] = {
    "es",
    "cs",
    "ss",
    "ds",
};

const char *opcode_mnemonics[] = {
    "(bad)",
    "aaa",
    "aad",
    "aam",
    "aas",
    "adc",
    "add",
    "and",
    "arpl",
    "bound",
    "call",
    "cbw",
    "clc",
    "cld",
    "cli",
    "clts",
    "cmc",
    "cmp",
    "cmpsb",
    "cmpsw",
    "cwd",
    "daa",
    "das",
    "dec",
    "div",
    "enter",
    "hlt",
    "idiv",
    "imul",
    "in",
    "inc",
    "insb",
    "insw",
    "int",
    "into",
    "iret",
    "jo",
    "jno",
    "jb",
    "jnb",
    "je",
    "jne",
    "jna",
    "ja",
    "js",
    "jns",
    "jp",
    "jnp",
    "jl",
    "jle",
    "jge",
    "jg",
    "jcxz",
    "jmp",
    "lahf",
    "lar",
    "lds",
    "les",
    "lea",
    "leave",
    "lgdt",
    "lidt",
    "lldt",
    "lmsw",
    "lodsb",
    "lodsw",
    "loop",
    "loopz",
    "loopnz",
    "lsl",
    "ltr",
    "mov",
    "movsb",
    "movsw",
    "mul",
    "neg",
    "nop",
    "not",
    "or",
    "out",
    "outsb",
    "outsw",
    "pop",
    "popa",
    "popf",
    "push",
    "pusha",
    "pushf",
    "rcl",
    "rcr",
    "ret",
    "retf",
    "rol",
    "ror",
    "sahf",
    "salc",
    "sal",
    "sar",
    "sbb",
    "scasb",
    "scasw",
    "shl",
    "shr",
    "sgdt",
    "sidt",
    "sldt",
    "smsw",
    "stc",
    "std",
    "sti",
    "stosb",
    "stosw",
    "str",
    "sub",
    "test",
    "verr",
    "verw",
    "wait",
    "xchg",
    "xlat",
    "xor",
    "lock",
    "rep",
    "repne",
    "cs",
    "ds",
    "es",
    "ss",
};

struct oper *oper_alloc(enum oper_flag flags)
{
    struct oper *oper = malloc(sizeof(struct oper));
    oper->flags = flags;
    oper->next = NULL;
    return oper;
}

struct oper *oper_alloc_imm8(uint8_t imm8)
{
    struct oper *oper = oper_alloc(I286_OPER_IMM8);
    oper->imm8 = imm8;
    return oper;
}

struct oper *oper_alloc_imm16(uint16_t imm16)
{
    struct oper *oper = oper_alloc(I286_OPER_IMM16);
    oper->imm16 = imm16;
    return oper;
}

struct oper *oper_alloc_imm32(uint16_t imm32)
{
    struct oper *oper = oper_alloc(I286_OPER_IMM32);
    oper->imm32 = imm32;
    return oper;
}

struct oper *oper_alloc_reg(enum reg reg)
{
    struct oper *oper = oper_alloc(I286_OPER_REG);
    oper->reg = reg;
    return oper;
}

struct oper *oper_alloc_seg(enum seg seg)
{
    struct oper *oper = oper_alloc(I286_OPER_SEG);
    oper->seg = seg;
    return oper;
}

bool insn_is_bad(struct insn *ins)
{
    return ins->op == I286_BAD;
}

bool insn_is_terminator(struct insn *ins)
{
    return ins->op == I286_JMP
        || ins->op == I286_RET
        || ins->op == I286_IRET;
}

bool insn_is_prefix(struct insn *ins)
{
    return ins->op == I286_PRE_LOCK
        || ins->op == I286_PRE_REP
        || ins->op == I286_PRE_REPNE
        || ins->op == I286_PRE_CS
        || ins->op == I286_PRE_DS
        || ins->op == I286_PRE_ES
        || ins->op == I286_PRE_SS;
}

bool insn_is_branch(struct insn *ins)
{
    switch (ins->op) {
        case I286_JO:
        case I286_JNO:
        case I286_JB:
        case I286_JNB:
        case I286_JE:
        case I286_JNE:
        case I286_JNA:
        case I286_JA:
        case I286_JS:
        case I286_JNS:
        case I286_JP:
        case I286_JNP:
        case I286_JL:
        case I286_JLE:
        case I286_JGE:
        case I286_JG:
        case I286_JCXZ:
        case I286_JMP:
        case I286_LOOP:
        case I286_LOOPZ:
        case I286_LOOPNZ:
        case I286_CALL:
            return true;
    }

    return insn_is_terminator(ins);
}

bool insn_get_branch(struct insn *ins, int32_t *target)
{
    switch (ins->op) {
        case I286_JO:
        case I286_JNO:
        case I286_JB:
        case I286_JNB:
        case I286_JE:
        case I286_JNE:
        case I286_JNA:
        case I286_JA:
        case I286_JS:
        case I286_JNS:
        case I286_JP:
        case I286_JNP:
        case I286_JL:
        case I286_JLE:
        case I286_JGE:
        case I286_JG:
        case I286_JCXZ:
            if (ins->opers->flags == I286_OPER_IMM16) {
                *target = ins->addr + ins->len + (int32_t)(int16_t)ins->opers->imm16;
                return true;
            }

            assert(ins->opers->flags == I286_OPER_IMM8);
            *target = ins->addr + ins->len + (int32_t)(int8_t)ins->opers->imm8;
            return true;

        case I286_JMP:
            if (ins->opers->flags == I286_OPER_IMM16) {
                *target = ins->addr + ins->len + (int32_t)(int16_t)ins->opers->imm16;
                return true;
            }

            if (ins->opers->flags == I286_OPER_IMM8) {
                *target = ins->addr + ins->len + (int32_t)(int8_t)ins->opers->imm8;
                return true;
            }

            assert(ins->opers->flags == I286_OPER_IMM32);
            *target = ins->opers->imm32 & 0xFFFF;
            return true;

        case I286_LOOP:
        case I286_LOOPZ:
        case I286_LOOPNZ:
            assert(ins->opers->flags == I286_OPER_IMM8);
            *target = ins->addr + ins->len + (int32_t)(int8_t)ins->opers->imm8;
            return true;

        case I286_CALL:
            if (ins->opers->flags == I286_OPER_IMM16) {
                *target = ins->addr + ins->len + (int32_t)(int16_t)ins->opers->imm16;
                return true;
            }
            break;
    }

    return false;
}

int oper_snprintf(char *buf, size_t size, struct oper *oper)
{
    int n = 0;

    switch (oper->flags) {
        case I286_OPER_IMM8:
            n += snprintf(buf, size, "%hhd", oper->imm8);
            break;

        case I286_OPER_IMM16:
            n += snprintf(buf, size, "%hd", oper->imm16);
            break;

        case I286_OPER_IMM32:
            n += snprintf(buf, size, "%d", oper->imm32);
            break;

        case I286_OPER_REG:
            n += snprintf(buf, size, "%s", reg_mnemonics[oper->reg]);
            break;

        case I286_OPER_SEG:
            n += snprintf(buf, size, "%s", seg_mnemonics[oper->seg]);
            break;

        case I286_OPER_MEM:
            n += snprintf(buf, size, "TODO");
            break;
    }

    return n;
}

int insn_snprintf(char *buf, size_t size, struct insn *ins)
{
    int n = snprintf(buf, size, "%s", opcode_mnemonics[ins->op]);
    if (insn_is_bad(ins))
        return n;

    // Special syntax
    if (ins->op == I286_JMP) {
        uint32_t addr = ins->addr + ins->len;
        switch (ins->opers->flags) {
            // Show relative or absolute?
            case I286_OPER_IMM8:
                addr += (int32_t)ins->opers->imm8;
                n += snprintf(buf + n, size - n, " short %x", addr);
                break;

            case I286_OPER_IMM16:
                addr += (int32_t)ins->opers->imm16;
                n += snprintf(buf + n, size - n, " near %x", addr);
                break;

            case I286_OPER_IMM32:
                n += snprintf(buf + n, size - n, " far %hx:%hx",
                        ins->opers->imm32 >> 16, ins->opers->imm32);
                break;

            default:
                n += snprintf(buf + n, size - n, " (bad)");
        }

        return n;
    }

    struct oper *oper = ins->opers;
    while (oper) {
        n += snprintf(buf + n, size - n, oper == ins->opers ? " " : ", ");
        n += oper_snprintf(buf + n, size - n, oper);
        oper = oper->next;
    }

    return n;
}

struct insn *insn_alloc(uint32_t addr)
{
    struct insn *ins = calloc(1, sizeof(struct insn));
    ins->addr = addr;
    return ins;
}

void dis_init(struct dis *dis, const uint8_t *bytes, uint32_t len, uint32_t base)
{
    memset(dis, 0, sizeof(struct dis));
    dis->base = base;
    dis->limit = len + base;
    dis->bytes = bytes;
    dis->decoded = calloc(len, sizeof(struct insn *));
}

void dis_push_entry(struct dis *dis, uint32_t entry)
{
    if (dis->entry_n >= DIS_ENTRY_N)
        return;

    dis->entry_list[dis->entry_n++] = entry;
}

bool dis_pop_entry(struct dis *dis, uint32_t *entry)
{
    if (dis->entry_n == 0)
        return false;

    *entry = dis->entry_list[--dis->entry_n];
    return true;
}

static bool try_fetch8(struct dis *dis, uint8_t *v)
{
    if (dis->ip >= dis->limit)
        return false;

    *v = dis->bytes[dis->ip - dis->base];
    dis->ip++;
    return true;
}

static bool try_fetch16(struct dis *dis, uint16_t *v)
{
    if (dis->ip + 1 >= dis->limit)
        return false;

    *v = (uint16_t)dis->bytes[dis->ip - dis->base]
       | ((uint16_t)dis->bytes[dis->ip + 1 - dis->base] << 8);

    dis->ip += 2;
    return true;
}

static bool try_fetch32(struct dis *dis, uint32_t *v)
{
    if (dis->ip + 3 >= dis->limit)
        return false;

    *v = (uint32_t)dis->bytes[dis->ip - dis->base]
       | ((uint32_t)dis->bytes[dis->ip + 1 - dis->base] << 8)
       | ((uint32_t)dis->bytes[dis->ip + 2 - dis->base] << 16)
       | ((uint32_t)dis->bytes[dis->ip + 3 - dis->base] << 24);

    dis->ip += 4;
    return true;
}

static enum reg get_reg(uint8_t reg, bool wide)
{
    switch (reg) {
        case 0:
            return wide ? I286_REG_AX : I286_REG_AL;

        case 1:
            return wide ? I286_REG_CX : I286_REG_CL;

        case 2:
            return wide ? I286_REG_DX : I286_REG_DL;

        case 3:
            return wide ? I286_REG_BX : I286_REG_BL;

        case 4:
            return wide ? I286_REG_SP : I286_REG_AH;

        case 5:
            return wide ? I286_REG_BP : I286_REG_CH;

        case 6:
            return wide ? I286_REG_SI : I286_REG_DH;

        case 7:
            return wide ? I286_REG_DI : I286_REG_BH;
    }

    assert(false && "Impossible reg value");
}

enum mem get_mem_mode(uint8_t rm, uint8_t mod)
{
    switch (rm) {
        case 0:
            return I286_MEM_DS_BX_SI;

        case 1:
            return I286_MEM_DS_BX_DI;

        case 2:
            return I286_MEM_SS_BP_SI;

        case 3:
            return I286_MEM_SS_BP_DI;

        case 4:
            return I286_MEM_DS_SI;

        case 5:
            return I286_MEM_DS_DI;

        case 6:
            return mod ? I286_MEM_ABS : I286_MEM_SS_BP;

        case 7:
            return I286_MEM_DS_BX;
    }

    assert(false && "Impossible mode value");
}

static bool try_modrm(struct dis *dis, uint8_t *reg, struct oper **oper_rm, bool wide)
{
    uint8_t modrm;
    if (!try_fetch8(dis, &modrm))
        return false;

    uint8_t mod = (modrm >> 6) & 0x3;
    *reg = (modrm >> 3) & 0x7;
    uint8_t rm = (modrm >> 0) & 0x7;

    *oper_rm = oper_alloc(I286_OPER_MEM);
    uint8_t lo, hi;
    int16_t disp = 0;

    // 00 : No displacement
    // 01 : 8-bit displacement
    // 10 : 16-bit displacement
    // 11 : Register
    switch (mod) {
        case 0:
            if (rm != 6)
                break;
            // When mod=00 and r/m=110 get absolute displacement
            // fall through

        case 2:
            if (!try_fetch8(dis, &hi) || !try_fetch8(dis, &lo))
                return false;

            disp = ((int16_t)hi << 8) | lo;
            break;

        case 1:
            if (!try_fetch8(dis, &lo))
                return false;

            // Sign extend to 16 bits
            disp = (int16_t)(int8_t)lo;
            break;

        case 3:
            (*oper_rm)->flags = I286_OPER_REG;
            (*oper_rm)->reg = get_reg(rm, wide);
            return true;
    }

    (*oper_rm)->mem.mode = get_mem_mode(rm, mod);
    (*oper_rm)->mem.disp = disp;
    return true;
}

// if dir then r/m -> reg else reg -> r/m
// if wide then reg16 else reg8

#define DIR_TO_RM  (0ul << 1)
#define DIR_TO_REG (1ul << 1)
#define REG_WIDE   (1ul << 0)

static bool try_modrm_full(struct dis *dis, struct oper **opers, int flags)
{
    struct oper *o_rm;
    uint8_t reg;

    bool wide = flags & REG_WIDE;
    if (!try_modrm(dis, &reg, &o_rm, wide))
        return false;

    struct oper *o_reg = oper_alloc_reg(get_reg(reg, wide));

    if (flags & DIR_TO_REG) {
        *o_reg->next = *o_rm;
        *opers = o_reg;
    } else {
        *o_rm->next = *o_reg;
        *opers = o_rm;
    }

    return true;
}

struct optab {
    bool (*decode)(struct dis *, struct insn *, uintptr_t);
    uintptr_t arg;
};

static bool decode_simple(struct dis *dis, struct insn *ins, uintptr_t arg)
{
    (void)dis;
    ins->op = arg;
    return true;
}

static bool decode_imm8(struct dis *dis, struct insn *ins, uintptr_t arg)
{
    ins->op = arg;
    ins->opers = oper_alloc(I286_OPER_IMM8);
    return try_fetch8(dis, &ins->opers->imm8);
}

static bool decode_imm16(struct dis *dis, struct insn *ins, uintptr_t arg)
{
    ins->op = arg;
    ins->opers = oper_alloc(I286_OPER_IMM16);
    return try_fetch16(dis, &ins->opers->imm16);
}

static bool decode_jmpfar(struct dis *dis, struct insn *ins, uintptr_t arg)
{
    // TODO: Maybe split segment and address?
    ins->op = arg;
    ins->opers = oper_alloc(I286_OPER_IMM32);
    return try_fetch32(dis, &ins->opers->imm32);
}

static bool decode_int(struct dis *dis, struct insn *ins, uintptr_t arg)
{
    ins->op = I286_INT;
    ins->opers = oper_alloc_imm8(arg);
    return arg || try_fetch8(dis, &ins->opers->imm8);
}

static bool decode_modrm(struct dis *dis, struct insn *ins, uintptr_t arg)
{
    ins->op = arg & 0xFFFF;
    return try_modrm_full(dis, &ins->opers, arg >> 32);
}

static bool decode_inout(struct dis *dis, struct insn *ins, uintptr_t arg)
{
    switch (arg) {
        case 0xEC:
            ins->op = I286_IN;
            ins->opers = oper_alloc_reg(I286_REG_AL);
            ins->opers->next = oper_alloc_reg(I286_REG_DX);
            return true;

        case 0xED:
            ins->op = I286_IN;
            ins->opers = oper_alloc_reg(I286_REG_AX);
            ins->opers->next = oper_alloc_reg(I286_REG_DX);
            return true;

        case 0xE4:
            ins->op = I286_IN;
            ins->opers = oper_alloc_reg(I286_REG_AL);
            ins->opers->next = oper_alloc(I286_OPER_IMM8);
            return try_fetch8(dis, &ins->opers->next->imm8);

        case 0xE5:
            ins->op = I286_IN;
            ins->opers = oper_alloc_reg(I286_REG_AX);
            ins->opers->next = oper_alloc(I286_OPER_IMM8);
            return try_fetch8(dis, &ins->opers->next->imm8);

        case 0xEE:
            ins->op = I286_OUT;
            ins->opers = oper_alloc_reg(I286_REG_DX);
            ins->opers->next = oper_alloc_reg(I286_REG_AL);
            return true;

        case 0xEF:
            ins->op = I286_OUT;
            ins->opers = oper_alloc_reg(I286_REG_DX);
            ins->opers->next = oper_alloc_reg(I286_REG_AX);
            return true;

        case 0xE6:
            ins->op = I286_OUT;
            ins->opers = oper_alloc(I286_OPER_IMM8);
            ins->opers->next = oper_alloc_reg(I286_REG_AL);
            return try_fetch8(dis, &ins->opers->imm8);

        case 0xE7:
            ins->op = I286_OUT;
            ins->opers = oper_alloc(I286_OPER_IMM8);
            ins->opers->next = oper_alloc_reg(I286_REG_AX);
            return try_fetch8(dis, &ins->opers->imm8);
    }

    return false;
}

static struct optab encodings[256] = {
	/* 0x00 */ { NULL, 0 },
	/* 0x01 */ { NULL, 0 },
	/* 0x02 */ { NULL, 0 },
	/* 0x03 */ { NULL, 0 },
	/* 0x04 */ { NULL, 0 },
	/* 0x05 */ { NULL, 0 },
	/* 0x06 */ { NULL, 0 },
	/* 0x07 */ { NULL, 0 },
	/* 0x08 */ { NULL, 0 },
	/* 0x09 */ { NULL, 0 },
	/* 0x0A */ { NULL, 0 },
	/* 0x0B */ { NULL, 0 },
	/* 0x0C */ { NULL, 0 },
	/* 0x0D */ { NULL, 0 },
	/* 0x0E */ { NULL, 0 },
	/* 0x0F */ { NULL, 0 },
	/* 0x10 */ { NULL, 0 },
	/* 0x11 */ { NULL, 0 },
	/* 0x12 */ { NULL, 0 },
	/* 0x13 */ { NULL, 0 },
	/* 0x14 */ { NULL, 0 },
	/* 0x15 */ { NULL, 0 },
	/* 0x16 */ { NULL, 0 },
	/* 0x17 */ { NULL, 0 },
	/* 0x18 */ { NULL, 0 },
	/* 0x19 */ { NULL, 0 },
	/* 0x1A */ { NULL, 0 },
	/* 0x1B */ { NULL, 0 },
	/* 0x1C */ { NULL, 0 },
	/* 0x1D */ { NULL, 0 },
	/* 0x1E */ { NULL, 0 },
	/* 0x1F */ { NULL, 0 },
	/* 0x20 */ { NULL, 0 },
	/* 0x21 */ { NULL, 0 },
	/* 0x22 */ { NULL, 0 },
	/* 0x23 */ { NULL, 0 },
	/* 0x24 */ { NULL, 0 },
	/* 0x25 */ { NULL, 0 },
	/* 0x26 */ { NULL, 0 },
	/* 0x27 */ { decode_simple, I286_DAA },
	/* 0x28 */ { NULL, 0 },
	/* 0x29 */ { NULL, 0 },
	/* 0x2A */ { NULL, 0 },
	/* 0x2B */ { NULL, 0 },
	/* 0x2C */ { NULL, 0 },
	/* 0x2D */ { NULL, 0 },
	/* 0x2E */ { NULL, 0 },
	/* 0x2F */ { decode_simple, I286_DAS },
	/* 0x30 */ { NULL, 0 },
	/* 0x31 */ { NULL, 0 },
	/* 0x32 */ { NULL, 0 },
	/* 0x33 */ { NULL, 0 },
	/* 0x34 */ { NULL, 0 },
	/* 0x35 */ { NULL, 0 },
	/* 0x36 */ { NULL, 0 },
	/* 0x37 */ { decode_simple, I286_AAA },
	/* 0x38 */ { NULL, 0 },
	/* 0x39 */ { NULL, 0 },
	/* 0x3A */ { NULL, 0 },
	/* 0x3B */ { NULL, 0 },
	/* 0x3C */ { NULL, 0 },
	/* 0x3D */ { NULL, 0 },
	/* 0x3E */ { NULL, 0 },
	/* 0x3F */ { decode_simple, I286_AAS },
	/* 0x40 */ { NULL, 0 },
	/* 0x41 */ { NULL, 0 },
	/* 0x42 */ { NULL, 0 },
	/* 0x43 */ { NULL, 0 },
	/* 0x44 */ { NULL, 0 },
	/* 0x45 */ { NULL, 0 },
	/* 0x46 */ { NULL, 0 },
	/* 0x47 */ { NULL, 0 },
	/* 0x48 */ { NULL, 0 },
	/* 0x49 */ { NULL, 0 },
	/* 0x4A */ { NULL, 0 },
	/* 0x4B */ { NULL, 0 },
	/* 0x4C */ { NULL, 0 },
	/* 0x4D */ { NULL, 0 },
	/* 0x4E */ { NULL, 0 },
	/* 0x4F */ { NULL, 0 },
	/* 0x50 */ { NULL, 0 },
	/* 0x51 */ { NULL, 0 },
	/* 0x52 */ { NULL, 0 },
	/* 0x53 */ { NULL, 0 },
	/* 0x54 */ { NULL, 0 },
	/* 0x55 */ { NULL, 0 },
	/* 0x56 */ { NULL, 0 },
	/* 0x57 */ { NULL, 0 },
	/* 0x58 */ { NULL, 0 },
	/* 0x59 */ { NULL, 0 },
	/* 0x5A */ { NULL, 0 },
	/* 0x5B */ { NULL, 0 },
	/* 0x5C */ { NULL, 0 },
	/* 0x5D */ { NULL, 0 },
	/* 0x5E */ { NULL, 0 },
	/* 0x5F */ { NULL, 0 },
	/* 0x60 */ { decode_simple, I286_PUSHA },
	/* 0x61 */ { decode_simple, I286_POPA },
	/* 0x62 */ { decode_modrm, I286_BOUND | (DIR_TO_RM | REG_WIDE) << 32 },
	/* 0x63 */ { decode_modrm, I286_ARPL | (DIR_TO_RM | REG_WIDE) << 32 },
	/* 0x64 */ { NULL, 0 },
	/* 0x65 */ { NULL, 0 },
	/* 0x66 */ { NULL, 0 },
	/* 0x67 */ { NULL, 0 },
	/* 0x68 */ { NULL, 0 },
	/* 0x69 */ { NULL, 0 },
	/* 0x6A */ { NULL, 0 },
	/* 0x6B */ { NULL, 0 },
	/* 0x6C */ { decode_simple, I286_INSB },
	/* 0x6D */ { decode_simple, I286_INSW },
	/* 0x6E */ { decode_simple, I286_OUTSB },
	/* 0x6F */ { decode_simple, I286_OUTSW },
	/* 0x70 */ { decode_imm8, I286_JO },
	/* 0x71 */ { decode_imm8, I286_JNO },
	/* 0x72 */ { decode_imm8, I286_JB },
	/* 0x73 */ { decode_imm8, I286_JNB },
	/* 0x74 */ { decode_imm8, I286_JE },
	/* 0x75 */ { decode_imm8, I286_JNE },
	/* 0x76 */ { decode_imm8, I286_JNA },
	/* 0x77 */ { decode_imm8, I286_JA },
	/* 0x78 */ { decode_imm8, I286_JS },
	/* 0x79 */ { decode_imm8, I286_JNS },
	/* 0x7A */ { decode_imm8, I286_JP },
	/* 0x7B */ { decode_imm8, I286_JNP },
	/* 0x7C */ { decode_imm8, I286_JL },
	/* 0x7D */ { decode_imm8, I286_JLE },
	/* 0x7E */ { decode_imm8, I286_JGE },
	/* 0x7F */ { decode_imm8, I286_JG },
	/* 0x80 */ { NULL, 0 },
	/* 0x81 */ { NULL, 0 },
	/* 0x82 */ { NULL, 0 },
	/* 0x83 */ { NULL, 0 },
	/* 0x84 */ { NULL, 0 },
	/* 0x85 */ { NULL, 0 },
	/* 0x86 */ { decode_modrm, I286_XCHG | DIR_TO_RM << 32 },
	/* 0x87 */ { decode_modrm, I286_XCHG | (DIR_TO_RM | REG_WIDE) << 32 },
	/* 0x88 */ { NULL, 0 },
	/* 0x89 */ { NULL, 0 },
	/* 0x8A */ { NULL, 0 },
	/* 0x8B */ { NULL, 0 },
	/* 0x8C */ { NULL, 0 },
	/* 0x8D */ { decode_modrm, I286_LEA | (DIR_TO_REG | REG_WIDE) << 32 },
	/* 0x8E */ { NULL, 0 },
	/* 0x8F */ { NULL, 0 },
	/* 0x90 */ { decode_simple, I286_NOP },
	/* 0x91 */ { NULL, 0 },
	/* 0x92 */ { NULL, 0 },
	/* 0x93 */ { NULL, 0 },
	/* 0x94 */ { NULL, 0 },
	/* 0x95 */ { NULL, 0 },
	/* 0x96 */ { NULL, 0 },
	/* 0x97 */ { NULL, 0 },
	/* 0x98 */ { decode_simple, I286_CBW },
	/* 0x99 */ { decode_simple, I286_CWD },
	/* 0x9A */ { decode_jmpfar, I286_CALL },
	/* 0x9B */ { decode_simple, I286_WAIT },
	/* 0x9C */ { decode_simple, I286_PUSHF },
	/* 0x9D */ { NULL, 0 },
	/* 0x9E */ { NULL, 0 },
	/* 0x9F */ { decode_simple, I286_LAHF },
	/* 0xA0 */ { NULL, 0 },
	/* 0xA1 */ { NULL, 0 },
	/* 0xA2 */ { NULL, 0 },
	/* 0xA3 */ { NULL, 0 },
	/* 0xA4 */ { decode_simple, I286_MOVSB },
	/* 0xA5 */ { decode_simple, I286_MOVSW },
	/* 0xA6 */ { decode_simple, I286_CMPSB },
	/* 0xA7 */ { decode_simple, I286_CMPSW },
	/* 0xA8 */ { NULL, 0 },
	/* 0xA9 */ { NULL, 0 },
	/* 0xAA */ { decode_simple, I286_STOSB },
	/* 0xAB */ { decode_simple, I286_STOSW },
	/* 0xAC */ { decode_simple, I286_LODSB },
	/* 0xAD */ { decode_simple, I286_LODSW },
	/* 0xAE */ { decode_simple, I286_SCASB },
	/* 0xAF */ { decode_simple, I286_SCASW },
	/* 0xB0 */ { NULL, 0 },
	/* 0xB1 */ { NULL, 0 },
	/* 0xB2 */ { NULL, 0 },
	/* 0xB3 */ { NULL, 0 },
	/* 0xB4 */ { NULL, 0 },
	/* 0xB5 */ { NULL, 0 },
	/* 0xB6 */ { NULL, 0 },
	/* 0xB7 */ { NULL, 0 },
	/* 0xB8 */ { NULL, 0 },
	/* 0xB9 */ { NULL, 0 },
	/* 0xBA */ { NULL, 0 },
	/* 0xBB */ { NULL, 0 },
	/* 0xBC */ { NULL, 0 },
	/* 0xBD */ { NULL, 0 },
	/* 0xBE */ { NULL, 0 },
	/* 0xBF */ { NULL, 0 },
	/* 0xC0 */ { NULL, 0 },
	/* 0xC1 */ { NULL, 0 },
	/* 0xC2 */ { decode_imm16, I286_RET },
	/* 0xC3 */ { decode_simple, I286_RET },
	/* 0xC4 */ { NULL, 0 },
	/* 0xC5 */ { NULL, 0 },
	/* 0xC6 */ { NULL, 0 },
	/* 0xC7 */ { NULL, 0 },
	/* 0xC8 */ { NULL, 0 },
	/* 0xC9 */ { decode_simple, I286_LEAVE },
	/* 0xCA */ { decode_imm16, I286_RETF },
	/* 0xCB */ { decode_simple, I286_RETF },
	/* 0xCC */ { decode_int, 3 },
	/* 0xCD */ { decode_int, 0 },
	/* 0xCE */ { decode_simple, I286_INTO },
	/* 0xCF */ { decode_simple, I286_IRET },
	/* 0xD0 */ { NULL, 0 },
	/* 0xD1 */ { NULL, 0 },
	/* 0xD2 */ { NULL, 0 },
	/* 0xD3 */ { NULL, 0 },
	/* 0xD4 */ { decode_imm8, I286_AAM },
	/* 0xD5 */ { decode_imm8, I286_AAD },
	/* 0xD6 */ { decode_simple, I286_SALC },
	/* 0xD7 */ { decode_simple, I286_XLAT },
	/* 0xD8 */ { NULL, 0 },
	/* 0xD9 */ { NULL, 0 },
	/* 0xDA */ { NULL, 0 },
	/* 0xDB */ { NULL, 0 },
	/* 0xDC */ { NULL, 0 },
	/* 0xDD */ { NULL, 0 },
	/* 0xDE */ { NULL, 0 },
	/* 0xDF */ { NULL, 0 },
	/* 0xE0 */ { decode_imm8, I286_LOOPNZ },
	/* 0xE1 */ { decode_imm8, I286_LOOPZ },
	/* 0xE2 */ { decode_imm8, I286_LOOP },
	/* 0xE3 */ { decode_imm8, I286_JCXZ },
	/* 0xE4 */ { decode_inout, 0xE4 },
	/* 0xE5 */ { decode_inout, 0xE5 },
	/* 0xE6 */ { decode_inout, 0xE6 },
	/* 0xE7 */ { decode_inout, 0xE7 },
	/* 0xE8 */ { decode_imm16, I286_CALL },
	/* 0xE9 */ { decode_imm16, I286_JMP },
	/* 0xEA */ { decode_jmpfar, I286_JMP },
	/* 0xEB */ { decode_imm8, I286_JMP },
	/* 0xEC */ { decode_inout, 0xEC },
	/* 0xED */ { decode_inout, 0xED },
	/* 0xEE */ { decode_inout, 0xEE },
	/* 0xEF */ { decode_inout, 0xEF },
	/* 0xF0 */ { NULL, 0 },
	/* 0xF1 */ { decode_int, 1 },
	/* 0xF2 */ { NULL, 0 },
	/* 0xF3 */ { NULL, 0 },
	/* 0xF4 */ { decode_simple, I286_HLT },
	/* 0xF5 */ { decode_simple, I286_CMC },
	/* 0xF6 */ { NULL, 0 },
	/* 0xF7 */ { NULL, 0 },
	/* 0xF8 */ { decode_simple, I286_CLC },
	/* 0xF9 */ { decode_simple, I286_STC },
	/* 0xFA */ { decode_simple, I286_CLI },
	/* 0xFB */ { decode_simple, I286_STI },
	/* 0xFC */ { decode_simple, I286_CLD },
	/* 0xFD */ { decode_simple, I286_STD },
	/* 0xFE */ { NULL, 0 },
	/* 0xFF */ { NULL, 0 },
};

struct insn *dis_decode(struct dis *dis)
{
    uint32_t start = dis->ip;
    struct insn *ins = insn_alloc(start);

    uint8_t op = dis->bytes[dis->ip++ - dis->base];
    struct optab *optab = &encodings[op];
    if (!optab->decode || !optab->decode(dis, ins, optab->arg))
        ins->op = I286_BAD;

    //if (ins->op == I286_BAD)
    //    dis->ip = start + 1;

    dis->decoded[start - dis->base] = ins;
    ins->len = dis->ip - start;
    return ins;
}

void dis_disasm(struct dis *dis)
{
    while (dis_pop_entry(dis, &dis->ip)) {
        while (dis->ip < dis->limit) {
            if (dis->decoded[dis->ip - dis->base])
                break;

            // Linear Sweep
            struct insn *ins = dis_decode(dis);
            if (insn_is_bad(ins))
                break;

            int32_t branch;
            if (insn_get_branch(ins, &branch))
                dis_push_entry(dis, branch);

            if (insn_is_terminator(ins))
                break;
        }
    }
}

bool dis_iterate(struct dis *dis, uint32_t *index, struct insn **ins)
{
    if (*index >= dis->limit - dis->base)
        return false;

    *ins = dis->decoded[*index];
    *index += *ins ? (*ins)->len : 1;
    return true;
}
