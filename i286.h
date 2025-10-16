#ifndef I286_H
#define I286_H

#include <stdint.h>

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

struct oper {
	union {
		uint8_t imm8;
		uint16_t imm16;
		uint32_t imm32;
		enum reg reg;
		struct {
			enum mem rm;
			uint16_t disp;
		} mem;
	};
	struct oper *next;
};

enum mnemonic {
};

struct instr {
	uint32_t addr;
	enum mnemonic name;
	struct oper *opers;
};

#endif
