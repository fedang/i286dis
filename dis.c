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
                *target = ins->addr + ins->len + (int32_t)ins->opers->imm16;
                return true;
            }

            assert(ins->opers->flags == I286_OPER_IMM8);
            *target = ins->addr + ins->len + (int32_t)ins->opers->imm8;
            return true;

        case I286_JMP:
            if (ins->opers->flags == I286_OPER_IMM16) {
                *target = ins->addr + ins->len + (int32_t)ins->opers->imm16;
                return true;
            }

            if (ins->opers->flags == I286_OPER_IMM8) {
                *target = ins->addr + ins->len + (int32_t)ins->opers->imm8;
                return true;
            }

            assert(ins->opers->flags == I286_OPER_IMM32);
            *target = ins->opers->imm32 & 0xFFFF;
            return true;

        case I286_LOOP:
        case I286_LOOPZ:
        case I286_LOOPNZ:
            assert(ins->opers->flags == I286_OPER_IMM8);
            *target = ins->addr + ins->len + (int32_t)ins->opers->imm8;
            return true;

        case I286_CALL:
            if (ins->opers->flags == I286_OPER_IMM16) {
                *target = ins->addr + ins->len + (int32_t)ins->opers->imm16;
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

#define DIR_TO_RM  0
#define DIR_TO_REG 1

// if dir then r/m -> reg else reg -> r/m
// if wide then reg16 else reg8
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

static bool try_modrm_full(struct dis *dis, struct oper **opers, bool dir, bool wide)
{

    struct oper *o_rm;
    uint8_t reg;

    if (!try_modrm(dis, &reg, &o_rm, wide))
        return false;

    struct oper *o_reg = oper_alloc_reg(get_reg(reg, wide));

    if (dir) {
        *o_reg->next = *o_rm;
        *opers = o_reg;
    } else {
        *o_rm->next = *o_reg;
        *opers = o_rm;
    }
    return true;
}

struct insn *dis_decode(struct dis *dis)
{
    uint32_t start = dis->ip;

    struct insn *ins = dis->decoded[start - dis->base];
    if (ins != NULL)
        return ins;

    ins = insn_alloc(start);
    ins->op = I286_BAD;

    uint8_t op = dis->bytes[dis->ip++ - dis->base];
    switch (op) {
        case 0x37:
            ins->op = I286_AAA;
            break;

        case 0xD5:
            ins->op = I286_AAD;
            ins->opers = oper_alloc(I286_OPER_IMM8);
            if (!try_fetch8(dis, &ins->opers->imm8))
                ins->op = I286_BAD;
            break;

        case 0xD4:
            ins->op = I286_AAM;
            ins->opers = oper_alloc(I286_OPER_IMM8);
            if (!try_fetch8(dis, &ins->opers->imm8))
                ins->op = I286_BAD;
            break;

        case 0x3F:
            ins->op = I286_AAS;
            break;

        case 0x63:
            ins->op = I286_ARPL;
            if (!try_modrm_full(dis, &ins->opers, DIR_TO_RM, true))
                ins->op = I286_BAD;
            break;

        case 0x62:
            ins->op = I286_BOUND;
            if (!try_modrm_full(dis, &ins->opers, DIR_TO_REG, true))
                ins->op = I286_BAD;
            break;

        // TODO: Other calls
        case 0xE8:
            ins->op = I286_CALL;
            ins->opers = oper_alloc(I286_OPER_IMM16);
            if (!try_fetch16(dis, &ins->opers->imm16))
                ins->op = I286_BAD;
            break;

        case 0x98:
            ins->op = I286_CBW;
            break;

        case 0x99:
            ins->op = I286_CWD;
            break;

        case 0xF8:
            ins->op = I286_CLC;
            break;

        case 0xFA:
            ins->op = I286_CLI;
            break;

        case 0xFC:
            ins->op = I286_CLD;
            break;

        // 2-byte opcodes
        case 0x0F:
            op = dis->bytes[dis->ip++ - dis->base];
            if (op == 0x06)
                ins->op = I286_CLTS;
            break;

        case 0xF5:
            ins->op = I286_CMC;
            break;

        case 0xA6:
            ins->op = I286_CMPSB;
            break;

        case 0xA7:
            ins->op = I286_CMPSW;
            break;

        case 0x27:
            ins->op = I286_DAA;
            break;

        case 0x2F:
            ins->op = I286_DAS;
            break;

        case 0xC8:
            ins->op = I286_ENTER;
            ins->opers = oper_alloc(I286_OPER_IMM16);
            if (!try_fetch16(dis, &ins->opers->imm16))
                ins->op = I286_BAD;

            ins->opers->next = oper_alloc(I286_OPER_IMM8);
            if (!try_fetch8(dis, &ins->opers->next->imm8))
                ins->op = I286_BAD;
            break;

        case 0xF4:
            ins->op = I286_HLT;
            break;

        case 0xEC:
            ins->op = I286_IN;
            ins->opers = oper_alloc_reg(I286_REG_AL);
            ins->opers->next = oper_alloc_reg(I286_REG_DX);
            break;

        case 0xED:
            ins->op = I286_IN;
            ins->opers = oper_alloc_reg(I286_REG_AX);
            ins->opers->next = oper_alloc_reg(I286_REG_DX);
            break;

        case 0xE4:
            ins->op = I286_IN;
            ins->opers = oper_alloc_reg(I286_REG_AL);
            ins->opers->next = oper_alloc(I286_OPER_IMM8);
            if (!try_fetch8(dis, &ins->opers->next->imm8))
                ins->op = I286_BAD;
            break;

        case 0xE5:
            ins->op = I286_IN;
            ins->opers = oper_alloc_reg(I286_REG_AX);
            ins->opers->next = oper_alloc(I286_OPER_IMM8);
            if (!try_fetch8(dis, &ins->opers->next->imm8))
                ins->op = I286_BAD;
            break;

        case 0x6C:
            ins->op = I286_INSB;
            break;

        case 0x6D:
            ins->op = I286_INSW;
            break;

        case 0xF1:
            ins->op = I286_INT;
            ins->opers = oper_alloc_imm8(1);
            break;

        case 0xCC:
            ins->op = I286_INT;
            ins->opers = oper_alloc_imm8(3);
            break;

        case 0xCD:
            ins->op = I286_INT;
            ins->opers = oper_alloc(I286_OPER_IMM8);
            if (!try_fetch8(dis, &ins->opers->imm8))
                ins->op = I286_BAD;
            break;

        case 0xCE:
            ins->op = I286_INTO;
            break;

        case 0xCF:
            ins->op = I286_IRET;
            break;

        case 0xE3:
            ins->op = I286_JCXZ;
            ins->opers = oper_alloc(I286_OPER_IMM8);
            if (!try_fetch8(dis, &ins->opers->imm8))
                ins->op = I286_BAD;
            break;

        case 0xE9:
            ins->op = I286_JMP;
            ins->opers = oper_alloc(I286_OPER_IMM16);
            if (!try_fetch16(dis, &ins->opers->imm16))
                ins->op = I286_BAD;
            break;

        case 0xEA:
            ins->op = I286_JMP;
            ins->opers = oper_alloc(I286_OPER_IMM32);
            if (!try_fetch32(dis, &ins->opers->imm32))
                ins->op = I286_BAD;
            break;

        case 0xEB:
            ins->op = I286_JMP;
            ins->opers = oper_alloc(I286_OPER_IMM8);
            if (!try_fetch8(dis, &ins->opers->imm8))
                ins->op = I286_BAD;
            break;

        case 0x9F:
            ins->op = I286_LAHF;
            break;

        case 0xC5:
            ins->op = I286_LDS;
            if (!try_modrm_full(dis, &ins->opers, DIR_TO_REG, true))
                ins->op = I286_BAD;
            break;

        case 0xC4:
            ins->op = I286_LES;
            if (!try_modrm_full(dis, &ins->opers, DIR_TO_REG, true))
                ins->op = I286_BAD;
            break;

        case 0x8D:
            ins->op = I286_LEA;
            if (!try_modrm_full(dis, &ins->opers, DIR_TO_REG, true))
                ins->op = I286_BAD;
            break;

        case 0xC9:
            ins->op = I286_LEAVE;
            break;

        case 0xAC:
            ins->op = I286_LODSB;
            break;

        case 0xAD:
            ins->op = I286_LODSW;
            break;

        case 0xE2:
            ins->op = I286_LOOP;
            ins->opers = oper_alloc(I286_OPER_IMM8);
            if (!try_fetch8(dis, &ins->opers->imm8))
                ins->op = I286_BAD;
            break;

        case 0xE1:
            ins->op = I286_LOOPZ;
            ins->opers = oper_alloc(I286_OPER_IMM8);
            if (!try_fetch8(dis, &ins->opers->imm8))
                ins->op = I286_BAD;
            break;

        case 0xE0:
            ins->op = I286_LOOPNZ;
            ins->opers = oper_alloc(I286_OPER_IMM8);
            if (!try_fetch8(dis, &ins->opers->imm8))
                ins->op = I286_BAD;
            break;

        case 0xA4:
            ins->op = I286_MOVSB;
            break;

        case 0xA5:
            ins->op = I286_MOVSW;
            break;

        case 0x90:
            ins->op = I286_NOP;
            break;

        case 0xEE:
            ins->op = I286_OUT;
            ins->opers = oper_alloc_reg(I286_REG_DX);
            ins->opers->next = oper_alloc_reg(I286_REG_AL);
            break;

        case 0xEF:
            ins->op = I286_OUT;
            ins->opers = oper_alloc_reg(I286_REG_DX);
            ins->opers->next = oper_alloc_reg(I286_REG_AX);
            break;

        case 0xE6:
            ins->op = I286_IN;
            ins->opers = oper_alloc(I286_OPER_IMM8);
            ins->opers->next = oper_alloc_reg(I286_REG_AL);
            if (!try_fetch8(dis, &ins->opers->imm8))
                ins->op = I286_BAD;
            break;

        case 0xE7:
            ins->op = I286_IN;
            ins->opers = oper_alloc(I286_OPER_IMM8);
            ins->opers->next = oper_alloc_reg(I286_REG_AX);
            if (!try_fetch8(dis, &ins->opers->imm8))
                ins->op = I286_BAD;
            break;

        case 0x6E:
            ins->op = I286_OUTSB;
            break;

        case 0x6F:
            ins->op = I286_OUTSW;
            break;

        case 0x61:
            ins->op = I286_POPA;
            break;

        case 0x9D:
            ins->op = I286_POPF;
            break;

        case 0x60:
            ins->op = I286_PUSHA;
            break;

        case 0x9C:
            ins->op = I286_PUSHF;
            break;

        case 0xC3:
            ins->op = I286_RET;
            break;

        case 0xC2:
            ins->op = I286_RET;
            ins->opers = oper_alloc(I286_OPER_IMM16);
            if (!try_fetch16(dis, &ins->opers->imm16))
                ins->op = I286_BAD;
            break;

        case 0xCB:
            ins->op = I286_RETF;
            break;

        case 0xCA:
            ins->op = I286_RET;
            ins->opers = oper_alloc(I286_OPER_IMM16);
            if (!try_fetch16(dis, &ins->opers->imm16))
                ins->op = I286_BAD;
            break;

        case 0xD6:
            ins->op = I286_SALC;
            break;

        case 0xAE:
            ins->op = I286_SCASB;
            break;

        case 0xAF:
            ins->op = I286_SCASW;
            break;

        case 0xF9:
            ins->op = I286_STC;
            break;

        case 0xFD:
            ins->op = I286_STD;
            break;

        case 0xFB:
            ins->op = I286_STI;
            break;

        case 0xAA:
            ins->op = I286_STOSB;
            break;

        case 0xAB:
            ins->op = I286_STOSW;
            break;

        case 0x9B:
            ins->op = I286_WAIT;
            break;

        case 0xD7:
            ins->op = I286_XLAT;
            break;

        case 0x86:
            ins->op = I286_XCHG;
            if (!try_modrm_full(dis, &ins->opers, DIR_TO_RM, false))
                ins->op = I286_BAD;
            break;

        case 0x87:
            ins->op = I286_XCHG;
            if (!try_modrm_full(dis, &ins->opers, DIR_TO_RM, true))
                ins->op = I286_BAD;
            break;
    }

    if (ins->op == I286_BAD)
        dis->ip = start + 1;

    dis->decoded[start - dis->base] = ins;
    ins->len = dis->ip - start;
    return ins;
}

void dis_disasm(struct dis *dis)
{
    while (dis_pop_entry(dis, &dis->ip)) {
        // Linear Sweep
        while (dis->ip < dis->limit) {
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
