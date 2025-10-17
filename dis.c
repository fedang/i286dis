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
        || ins->op == I286_JMPF
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
        case I286_CALL:
        case I286_CALLF:
        case I286_LOOP:
        case I286_LOOPZ:
        case I286_LOOPNZ:
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
        case I286_JMPF:
            return true;
    }

    return insn_is_terminator(ins);
}

bool insn_get_branch(struct insn *ins, int32_t *target)
{
    switch (ins->op) {
        case I286_CALL:
            if (ins->opers->flags == I286_OPER_IMM16) {
                *target = ins->addr + ins->len + (int32_t)(int16_t)ins->opers->imm16;
                return true;
            }
            break;

        case I286_CALLF:
            if (ins->opers->flags == I286_OPER_IMM32) {
                *target = (ins->opers->imm32 >> 16) << 4
                        | (ins->opers->imm32 & 0xFFFF);
                return true;
            }
            break;

        case I286_LOOP:
        case I286_LOOPZ:
        case I286_LOOPNZ:
            assert(ins->opers->flags == I286_OPER_IMM8);
            *target = ins->addr + ins->len + (int32_t)(int8_t)ins->opers->imm8;
            return true;

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
            break;

        case I286_JMPF:
            if (ins->opers->flags == I286_OPER_IMM32) {
                *target = (ins->opers->imm32 >> 16) << 4
                        | (ins->opers->imm32 & 0xFFFF);
                return true;
            }
            break;
    }

    return false;
}

static int mem_snprintf(char *buf, size_t size, struct oper *oper)
{
    const char *seg = "";
    const char *base = "";

    switch (oper->mem.mode) {
        case I286_MEM_ABS:
        case I286_MEM_MOFF:
            break;

        case I286_MEM_DS_BX_SI:
            base = "bx + si";
            break;

        case I286_MEM_DS_BX_DI:
            base = "bx + di";
            break;

        case I286_MEM_SS_BP_SI:
            seg = "ss:";
            base = "bp + si";
            break;

        case I286_MEM_SS_BP_DI:
            seg = "ss:";
            base = "bp + di";
            break;

        case I286_MEM_DS_SI:
            base = "si";
            break;

        case I286_MEM_DS_DI:
            base = "di";
            break;

        case I286_MEM_SS_BP:
            seg = "ss:";
            base = "bp";
            break;

        case I286_MEM_DS_BX:
            base = "bx";
            break;
    }

    if (*base == 0)
        return snprintf(buf, size, "%s[0x%hx]", seg, oper->mem.disp);

    char sign = oper->mem.disp < 0 ? '-' : '+';
    uint16_t disp = abs(oper->mem.disp);

    if (disp == 0)
        return snprintf(buf, size, "%s[%s]", seg, base);

    return snprintf(buf, size, "%s[%s %c 0x%hx]", seg, base, sign, disp);
}

int oper_snprintf(char *buf, size_t size, struct oper *oper)
{
    int n = 0;
    switch (oper->flags) {
        case I286_OPER_IMM8:
            n += snprintf(buf, size, "%hhu", oper->imm8);
            break;

        case I286_OPER_IMM16:
            n += snprintf(buf, size, "0x%hx", oper->imm16);
            break;

        case I286_OPER_IMM32:
            n += snprintf(buf, size, "0x%x", oper->imm32);
            break;

        case I286_OPER_REG:
            n += snprintf(buf, size, "%s", reg_mnemonics[oper->reg]);
            break;

        case I286_OPER_SEG:
            n += snprintf(buf, size, "%s", seg_mnemonics[oper->seg]);
            break;

        case I286_OPER_MEM:
            n += mem_snprintf(buf, size, oper);
            break;
    }

    return n;
}

static int branch_snprintf(char *buf, size_t size, struct insn *ins)
{
    int n = 0;
    if (ins->op == I286_JMPF || ins->op == I286_CALLF) {
        if (ins->opers->flags == I286_OPER_IMM32) {
            n += snprintf(buf + n, size - n, " far 0x%hx:0x%hx",
                    ins->opers->imm32 >> 16, ins->opers->imm32);
        } else {
            n += snprintf(buf + n, size - n, " far ");
            n += oper_snprintf(buf + n, size - n, ins->opers);
        }
        return n;
    }

    uint32_t addr = ins->addr + ins->len;
    if (ins->opers->flags == I286_OPER_IMM8) {
        addr += (int32_t)(int8_t)ins->opers->imm8;
        n += snprintf(buf + n, size - n, " short %hhd ; 0x%x", ins->opers->imm8, addr);
    } else if (ins->opers->flags == I286_OPER_IMM16) {
        addr += (int32_t)(int16_t)ins->opers->imm16;
        n += snprintf(buf + n, size - n, " near %hd ; 0x%x", ins->opers->imm16, addr);
    } else {
        n += snprintf(buf + n, size - n, " word ");
        n += oper_snprintf(buf + n, size - n, ins->opers);
    }

    return n;
}

int insn_snprintf(char *buf, size_t size, struct insn *ins)
{
    int n = snprintf(buf, size, "%s", opcode_mnemonics[ins->op]);
    if (insn_is_bad(ins))
        return n;

    if (insn_is_branch(ins))
        return n + branch_snprintf(buf + n, size - n, ins);

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
