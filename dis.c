#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "i286dis.h"

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
    "popf",
    "push",
    "pusha",
    "pushf",
    "rcl",
    "rcr",
    "ret",
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

struct oper *oper_alloc_reg(uint16_t reg)
{
    struct oper *oper = oper_alloc(I286_OPER_REG);
    oper->reg = reg;
    return oper;
}

struct oper *oper_alloc_seg(uint16_t seg)
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

int insn_snprintf(char *buf, size_t size, struct insn *ins)
{
    int n = snprintf(buf, size, "%s", opcode_mnemonics[ins->op]);

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

        switch (oper->flags) {
            case I286_OPER_IMM8:
                break;

            case I286_OPER_IMM16:
                break;

            case I286_OPER_IMM32:
                break;

            case I286_OPER_REG:
                break;

            case I286_OPER_SEG:
                break;

            case I286_OPER_MEM:
                break;
        }

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

struct insn *dis_decode(struct dis *dis)
{
    uint32_t start = dis->ip;
    uint8_t op = dis->bytes[dis->ip++ - dis->base];

    struct insn *ins = insn_alloc(start);
    ins->op = I286_BAD;

    switch (op) {
        case 0xF8:
            ins->op = I286_CLC;
            break;

        case 0xFA:
            ins->op = I286_CLI;
            break;

        case 0xFC:
            ins->op = I286_CLD;
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
