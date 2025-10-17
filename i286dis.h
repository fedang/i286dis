#ifndef I286DIS_H
#define I286DIS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

enum reg {
	I286_REG_AL,
	I286_REG_AH,
	I286_REG_BL,
	I286_REG_BH,
	I286_REG_CL,
	I286_REG_CH,
	I286_REG_DL,
	I286_REG_DH,
	I286_REG_AX,
	I286_REG_BX,
	I286_REG_CX,
	I286_REG_DX,
	I286_REG_SP,
	I286_REG_BP,
	I286_REG_SI,
	I286_REG_DI,
};

enum seg {
	I286_SEG_ES,
	I286_SEG_CS,
	I286_SEG_SS,
	I286_SEG_DS,
};

enum mem {
    I286_MEM_ABS,
    I286_MEM_DS_BX_SI,
    I286_MEM_DS_BX_DI,
    I286_MEM_SS_BP_SI,
    I286_MEM_SS_BP_DI,
    I286_MEM_DS_SI,
    I286_MEM_DS_DI,
    I286_MEM_SS_BP,
    I286_MEM_DS_BX,
};

enum oper_flag {
    I286_OPER_IMM8,
    I286_OPER_IMM16,
    I286_OPER_IMM32,
    I286_OPER_REG,
    I286_OPER_SEG,
    I286_OPER_MEM,
};

struct oper {
    enum oper_flag flags;
	union {
		uint8_t imm8;
		uint16_t imm16;
		uint32_t imm32;
		enum reg reg;
		enum seg seg;
		struct {
			enum mem mode;
			int16_t disp;
		} mem;
	};
	struct oper *next;
};

enum opcode {
    I286_BAD,
    I286_AAA,
    I286_AAD,
    I286_AAM,
    I286_AAS,
    I286_ADC,
    I286_ADD,
    I286_AND,
    I286_ARPL,
    I286_BOUND,
    I286_CALL,
    I286_CBW,
    I286_CLC,
    I286_CLD,
    I286_CLI,
    I286_CLTS,
    I286_CMC,
    I286_CMP,
    I286_CMPSB,
    I286_CMPSW,
    I286_CWD,
    I286_DAA,
    I286_DAS,
    I286_DEC,
    I286_DIV,
    I286_ENTER,
    I286_HLT,
    I286_IDIV,
    I286_IMUL,
    I286_IN,
    I286_INC,
    I286_INSB,
    I286_INSW,
    I286_INT,
    I286_INTO,
    I286_IRET,
    I286_JO,
    I286_JNO,
    I286_JB,
    I286_JNB,
    I286_JE,
    I286_JNE,
    I286_JNA,
    I286_JA,
    I286_JS,
    I286_JNS,
    I286_JP,
    I286_JNP,
    I286_JL,
    I286_JLE,
    I286_JGE,
    I286_JG,
    I286_JCXZ,
    I286_JMP,
    I286_LAHF,
    I286_LAR,
    I286_LDS,
    I286_LES,
    I286_LEA,
    I286_LEAVE,
    I286_LGDT,
    I286_LIDT,
    I286_LLDT,
    I286_LMSW,
    I286_LODSB,
    I286_LODSW,
    I286_LOOP,
    I286_LOOPZ,
    I286_LOOPNZ,
    I286_LSL,
    I286_LTR,
    I286_MOV,
    I286_MOVSB,
    I286_MOVSW,
    I286_MUL,
    I286_NEG,
    I286_NOP,
    I286_NOT,
    I286_OR,
    I286_OUT,
    I286_OUTSB,
    I286_OUTSW,
    I286_POP,
    I286_POPA,
    I286_POPF,
    I286_PUSH,
    I286_PUSHA,
    I286_PUSHF,
    I286_RCL,
    I286_RCR,
    I286_RET,
    I286_RETF,
    I286_ROL,
    I286_ROR,
    I286_SAHF,
    I286_SALC,
    I286_SAL,
    I286_SAR,
    I286_SBB,
    I286_SCASB,
    I286_SCASW,
    I286_SHL,
    I286_SHR,
    I286_SGDT,
    I286_SIDT,
    I286_SLDT,
    I286_SMSW,
    I286_STC,
    I286_STD,
    I286_STI,
    I286_STOSB,
    I286_STOSW,
    I286_STR,
    I286_SUB,
    I286_TEST,
    I286_VERR,
    I286_VERW,
    I286_WAIT,
    I286_XCHG,
    I286_XLAT,
    I286_XOR,
    I286_PRE_LOCK,
    I286_PRE_REP,
    I286_PRE_REPNE,
    I286_PRE_CS,
    I286_PRE_DS,
    I286_PRE_ES,
    I286_PRE_SS,
};

struct insn {
	uint32_t addr;
    uint8_t len;
	enum opcode op;
	struct oper *opers;
};

#define DIS_ENTRY_N 32

struct dis {
    uint32_t ip;
    uint32_t base;
    uint32_t limit;
    const uint8_t *bytes;
    uint32_t entry_list[DIS_ENTRY_N];
    uint32_t entry_n;
    struct insn **decoded;
};

extern const char *reg_mnemonics[];

extern const char *seg_mnemonics[];

extern const char *opcode_mnemonics[];

struct oper *oper_alloc(enum oper_flag flags);

struct oper *oper_alloc_imm8(uint8_t imm8);

struct oper *oper_alloc_imm16(uint16_t imm16);

struct oper *oper_alloc_imm32(uint16_t imm32);

struct oper *oper_alloc_reg(enum reg reg);

struct oper *oper_alloc_seg(enum seg seg);

bool insn_is_bad(struct insn *ins);

bool insn_is_terminator(struct insn *ins);

bool insn_is_prefix(struct insn *ins);

bool insn_is_branch(struct insn *ins);

bool insn_get_branch(struct insn *ins, int32_t *target);

int insn_snprintf(char *buf, size_t size, struct insn *ins);

struct insn *insn_alloc(uint32_t addr);

void dis_init(struct dis *dis, const uint8_t *bytes, uint32_t len, uint32_t base);

void dis_push_entry(struct dis *dis, uint32_t entry);

bool dis_pop_entry(struct dis *dis, uint32_t *entry);

struct insn *dis_decode(struct dis *dis);

void dis_disasm(struct dis *dis);

bool dis_iterate(struct dis *dis, uint32_t *index, struct insn **ins);

#endif
