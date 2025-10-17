#include <stdio.h>
#include <ctype.h>

#include "i286dis.h"

void disasm(uint8_t *bytes, size_t len)
{
    struct dis dis;
    dis_init(&dis, bytes, len, 0x7c00);
    dis_push_entry(&dis, 0x7c00);
    dis_disasm(&dis);

    char buf[0x100];
    uint32_t off = 0;

    struct insn *ins;
    uint32_t idx = 0;

    while (dis_iterate(&dis, &idx, &ins)) {
        if (!ins) {
            uint8_t byte = bytes[idx - 1];
            printf("%x: %02hhx\t\t\tdb ", idx + dis.base - 1, byte);
            if (isprint(byte))
                printf("'%c'\n", byte);
            else
                printf("'\\x%hhx'\n", byte);
            continue;
        }

        printf("%x:", ins->addr);
        off = 0;

        while (insn_is_prefix(ins)) {
            printf(" %02x", bytes[idx - 1]);

            off += snprintf(buf + off, sizeof(buf) - off, "%s ", opcode_mnemonics[ins->op]);

            if (!dis_iterate(&dis, &idx, &ins) || !ins)
                break;
        }

        for (int i = 0; i < ins->len; i++)
            printf(" %02x", bytes[idx - ins->len + i]);

        insn_snprintf(buf + off, sizeof(buf) - off, ins);
        printf("\t\t\t%s\n", buf);
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

	uint8_t buf[442];
    size_t len = fread(buf, 1, sizeof(buf), fp);
	if (len == 0) {
		fprintf(stderr, "Could not read the file\n");
		fclose(fp);
		return 1;
	}

	fclose(fp);
	disasm(buf, len);
	return 0;
}
