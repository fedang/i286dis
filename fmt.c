#include <stdlib.h>
#include <stdio.h>
#include <string.h>

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

void fmt_init(struct fmt *fmt, enum fmt_flag flags)
{
    memset(fmt, 0, sizeof(struct fmt));
    fmt->flags = flags;
}

bool fmt_is_done(struct fmt *fmt)
{
    return fmt->state < 0 || fmt->last == NULL;
}

static int fmt_memory(struct fmt *fmt, struct oper *oper, char *buf, size_t size)
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

    bool hex = fmt->flags & FMT_HEX_DISP;
    if (*base == 0)
        return snprintf(buf, size, hex ? "%s[0x%hx]" : "%s[%hu]",
                        seg, oper->mem.disp);

    char sign = oper->mem.disp < 0 ? '-' : '+';
    uint16_t disp = abs(oper->mem.disp);

    if (disp == 0)
        return snprintf(buf, size, "%s[%s]", seg, base);

    return snprintf(buf, size, hex ? "%s[%s %c 0x%hx]" : "%s[%s %c %hu]",
                    seg, base, sign, disp);
}

static int fmt_oper(struct fmt *fmt, struct oper *oper, char *buf, size_t size)
{
    bool hex = fmt->flags & FMT_HEX_IMM;
    int n = 0, sum = 0;

    if (fmt->oper_pre) {
        n = fmt->oper_pre(buf, size, oper);
        if (n < 0 || (unsigned)n > size)
            return -1;

        buf += n;
        size -= n;
        sum += n;
    }

    switch (oper->flags) {
        case I286_OPER_IMM8:
            n = snprintf(buf, size, hex ? "0x%hhx" : "%hhu", oper->imm8);
            break;

        case I286_OPER_IMM16:
            n = snprintf(buf, size, hex ? "0x%hx" : "%hu", oper->imm16);
            break;

        case I286_OPER_IMM32:
            n = snprintf(buf, size, hex ? "0x%x" : "%u", oper->imm32);
            break;

        case I286_OPER_REG:
            n = snprintf(buf, size, "%s", reg_mnemonics[oper->reg]);
            break;

        case I286_OPER_SEG:
            n = snprintf(buf, size, "%s", seg_mnemonics[oper->seg]);
            break;

        case I286_OPER_MEM:
            n = fmt_memory(fmt, oper, buf, size);
            break;
    }

    sum += n;
    if (n < 0 || (unsigned)n > size) {
        return -1;
    }

    if (fmt->oper_post) {
        buf += n;
        size -= n;
        n = fmt->oper_post(buf, size, oper);
        if (n < 0 || (unsigned)n > size)
            return -1;
        sum += n;
    }

    return sum;
}

static int fmt_branch(struct fmt *fmt, struct insn *ins, char *buf, size_t size)
{
    bool jtype = fmt->flags & FMT_JMP_TYPE;
    bool jaddr = fmt->flags & FMT_JMP_ADDR;
    bool jboth = fmt->flags & FMT_JMP_BOTH;

    if (ins->op == I286_JMPF || ins->op == I286_CALLF) {
        if (fmt->state == 1 && jtype) {
            fmt->state++;
            return snprintf(buf, size, "far");
        }

        fmt->state = -1;
        if (ins->opers->flags == I286_OPER_IMM32) {
            return snprintf(buf, size, "0x%hx:0x%hx",
                ins->opers->imm32 >> 16, ins->opers->imm32);
        }

        return fmt_oper(fmt, ins->opers, buf, size);
    }

    uint32_t addr = ins->addr + ins->len;
    if (ins->opers->flags == I286_OPER_IMM8) {
        if (fmt->state == 1 && jtype) {
            fmt->state++;
            return snprintf(buf, size, "short");
        }

        addr += (int32_t)(int8_t)ins->opers->imm8;
        if (jboth) {
            if (fmt->state < 2)
                fmt->state = 2;

            if (fmt->state == 3) {
                fmt->state = -1;
                return snprintf(buf, size, "; 0x%x", addr);
            }

            fmt->state++;
            return snprintf(buf, size, "%hhd", ins->opers->imm8);
        }

        fmt->state = -1;
        if (jaddr)
            return snprintf(buf, size, "0x%x", addr);

        return snprintf(buf, size, "%hhd", ins->opers->imm8);
    } else if (ins->opers->flags == I286_OPER_IMM16) {
        if (fmt->state == 1 && jtype) {
            fmt->state++;
            return snprintf(buf, size, "near");
        }

        addr += (int32_t)(int16_t)ins->opers->imm16;
        if (jboth) {
            if (fmt->state < 2)
                fmt->state = 2;

            if (fmt->state == 3) {
                fmt->state = -1;
                return snprintf(buf, size, "; 0x%x", addr);
            }

            fmt->state++;
            return snprintf(buf, size, "%hd", ins->opers->imm16);
        }

        fmt->state = -1;
        if (jaddr)
            return snprintf(buf, size, "0x%x", addr);

        return snprintf(buf, size, "%hd", ins->opers->imm16);
    } else {
        if (fmt->state == 1 && jtype) {
            fmt->state++;
            return snprintf(buf, size, "word");
        }

        fmt->state = -1;
        return fmt_oper(fmt, ins->opers, buf, size);
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

    int n = 0, sum = 0;
    if (fmt->state == 0) {
        fmt->state = ins->opers ? fmt->state + 1 : -1;

        if (fmt->opcode_pre) {
            n = fmt->opcode_pre(buf, size, ins);
            if (n < 0 || (unsigned)n > size)
                return -1;

            buf += n;
            size -= n;
            sum += n;
        }

        n = snprintf(buf, size, "%s", opcode_mnemonics[ins->op]);
        if (n < 0 || (unsigned)n > size)
            return -1;

        sum += n;
        if (fmt->opcode_post) {
            buf += n;
            size -= n;
            n = fmt->opcode_post(buf, size, ins);
            if (n < 0 || (unsigned)n > size)
                return -1;
            sum += n;
        }

        return sum;
    }

    if (insn_is_branch(ins) && ins->op != I286_RET && ins->op != I286_RETF)
        return fmt_branch(fmt, ins, buf, size);

    struct oper *oper = ins->opers;
    for (int i = 0; oper; oper = oper->next) {
        if (++i == fmt->state) {
            fmt->state = oper->next ? fmt->state + 1 : -1;
            return fmt_oper(fmt, oper, buf, size);
        }
    }

    fmt->state = -1;
    return 0;
}

int fmt_insn(struct fmt *fmt, struct insn *ins, char *buf, size_t size)
{
    char *start = buf;
    for (int i = 0; ; i++) {
        int n = fmt_iterate(fmt, ins, buf, size);
        if (n <= 0 || (unsigned)n > size)
            return buf - start;

        buf += n;
        size -= n;

        if (!fmt_is_done(fmt)) {
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
