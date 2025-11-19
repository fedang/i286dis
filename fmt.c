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
            n += snprintf(buf, size, "0x%hhx", oper->imm8);
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

int insn_snprintf(char *buf, size_t size, struct insn *ins)
{
    struct fmt fmt;
    fmt_init(&fmt);

    char *start = buf;
    for (int i = 0; ; i++) {
        int n = fmt_iterate(&fmt, ins, buf, size);
        if (n <= 0 || (unsigned)n > size)
            return buf - start;

        buf += n;
        size -= n;

        if (!fmt_is_done(&fmt)) {
            if (i >= 0) {
                bool sep = i == 0 || insn_is_branch(ins);
                int n = snprintf(buf, size, sep ? " " : ", ");
                if (n <= 0 || (unsigned)n > size)
                    return buf - start;

                buf += n;
                size -= n;
            }
        }
    }

    return -1;
}

void fmt_init(struct fmt *fmt)
{
    fmt->last = NULL;
    fmt->state = 0;
}

static int fmt_branch(struct fmt *fmt, struct insn *ins, char *buf, size_t size)
{
    if (ins->op == I286_JMPF || ins->op == I286_CALLF) {
        if (fmt->state == 1) {
            fmt->state++;
            return snprintf(buf, size, "far");
        }

        fmt->state = -1;
        if (ins->opers->flags == I286_OPER_IMM32) {
            return snprintf(buf, size, "0x%hx:0x%hx",
                ins->opers->imm32 >> 16, ins->opers->imm32);
        }

        return oper_snprintf(buf, size, ins->opers);
    }

    uint32_t addr = ins->addr + ins->len;
    if (ins->opers->flags == I286_OPER_IMM8) {
        if (fmt->state == 1) {
            fmt->state++;
            return snprintf(buf, size, "short");
        }

        fmt->state = -1;
        addr += (int32_t)(int8_t)ins->opers->imm8;
        return snprintf(buf, size, "%hhd ; 0x%x", ins->opers->imm8, addr);
    } else if (ins->opers->flags == I286_OPER_IMM16) {
        if (fmt->state == 1) {
            fmt->state++;
            return snprintf(buf, size, "near");
        }

        fmt->state = -1;
        addr += (int32_t)(int16_t)ins->opers->imm16;
        return snprintf(buf, size, "%hd ; 0x%x", ins->opers->imm16, addr);
    } else {
        if (fmt->state == 1) {
            fmt->state++;
            return snprintf(buf, size, "word");
        }

        fmt->state = -1;
        return oper_snprintf(buf, size, ins->opers);
    }
}

int fmt_iterate(struct fmt *fmt, struct insn *ins, char *buf, size_t size)
{
    if (fmt->last != ins) {
        fmt->last = ins;
        fmt->state = 0;
    }

    if (fmt_is_done(fmt))
        return 0;

    if (fmt->state == 0) {
        fmt->state = ins->opers ? fmt->state + 1 : -1;
        return snprintf(buf, size, "%s", opcode_mnemonics[ins->op]);
    }

    if (insn_is_branch(ins) && ins->op != I286_RET && ins->op != I286_RETF)
        return fmt_branch(fmt, ins, buf, size);

    struct oper *oper = ins->opers;
    for (int i = 0; oper; oper = oper->next) {
        if (++i == fmt->state) {
            fmt->state = oper->next ? fmt->state + 1 : -1;
            return oper_snprintf(buf, size, oper);
        }
    }

    fmt->state = -1;
    return 0;
}

bool fmt_is_done(struct fmt *fmt)
{
    return fmt->state < 0 || fmt->last == NULL;
}
