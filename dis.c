#include <assert.h>
#include <string.h>
#include <stdlib.h>

#include "i286.h"

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

bool insn_get_branch(struct insn *ins, int16_t *disp)
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
                *disp = ins->opers->imm16;
                return true;
            }

            assert(ins->opers->flags == I286_OPER_IMM8);
            *disp = ins->opers->imm8;
            return true;

        case I286_JMP:
            if (ins->opers->flags == I286_OPER_IMM16) {
                *disp = ins->opers->imm16;
                return true;
            }

            if (ins->opers->flags == I286_OPER_IMM8) {
                *disp = ins->opers->imm8;
                return true;
            }
            break;

        case I286_LOOP:
        case I286_LOOPZ:
        case I286_LOOPNZ:
            assert(ins->opers->flags == I286_OPER_IMM8);
            *disp = ins->opers->imm8;
            return true;

        case I286_CALL:
            if (ins->opers->flags == I286_OPER_IMM16) {
                *disp = ins->opers->imm16;
                return true;
            }
            break;
    }

    return false;
}

struct insn *insn_alloc(uint32_t ip)
{
    struct insn *ins = calloc(1, sizeof(struct insn));
    ins->addr = ip;
    return ins;
}

void dis_init(struct dis *dis, const uint8_t *bytes, uint32_t len, uint32_t base)
{
    memset(dis, 0, sizeof(struct dis));
    dis->base = base;
    dis->bytes = bytes;
    dis->len = len;
    dis->decoded = malloc(len * sizeof(struct insn *));
}

void dis_push_entry(struct dis *dis, uint32_t entry)
{
    if (dis->entry_n == DIS_ENTRY_N)
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

struct insn *dis_decode(struct dis *dis)
{
    uint32_t start = dis->ip;

    struct insn *ins = insn_alloc(start);
    ins->op = I286_BAD;
    ins->len = 1;

    dis->ip++;

    dis->decoded[start - dis->base] = ins;
    return ins;
}

void dis_disasm(struct dis *dis)
{
    uint32_t limit = dis->base + dis->len;

    while (dis_pop_entry(dis, &dis->ip)) {
        // Linear Sweep
        while (dis->ip < limit) {
            struct insn *ins = dis_decode(dis);

            if (insn_is_bad(ins))
                break;

            int16_t branch;
            if (insn_get_branch(ins, &branch))
                dis_push_entry(dis, dis->ip + branch);


            if (insn_is_terminator(ins))
                break;
        }
    }
}

#include <stdio.h>

void disasm(uint8_t *bytes, size_t len)
{
    struct dis dis;
    dis_init(&dis, bytes, len, 0x7c00);
    dis_push_entry(&dis, 0x7c00);
    dis_disasm(&dis);

    size_t i = 0;
    while (i < len) {
        struct insn *ins = dis.decoded[i];
        if (!ins) {
            i++;
            continue;
        }

        printf("%d\n", ins->op);

        i += ins->len;
    }
}

int main(int argc, char **argv)
{
	if (argc != 2) {
		fprintf(stderr, "Usage: %s file\n", argv[0]);
		return 1;
	}

	FILE *fp = fopen(argv[1], "rb");
	if (!fp) {
		perror("Failed to open file");
		return 1;
	}

	char buf[400];
	if (fread(buf, sizeof(buf), 1, fp) != 1) {
		fprintf(stderr, "Could not read the MBR\n");
		fclose(fp);
		return 1;
	}

	disasm(buf, sizeof(buf));

	fclose(fp);
	return 0;
}

