#include <stdio.h>

#include "i286dis.h"

void disasm(uint8_t *bytes, size_t len)
{
    struct dis dis;
    dis_init(&dis, bytes, len, 0x7c00);
    dis_push_entry(&dis, 0x7c00);
    dis_disasm(&dis);

    char buf[100];

    uint32_t idx = 0;
    struct insn *ins;

    while (dis_iterate(&dis, &idx, &ins)) {
        if (!ins)
            continue;

        insn_snprintf(buf, sizeof(buf), ins);
        printf("%x %x: %s\n", idx, ins->addr, buf);
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

	uint8_t buf[400];
	if (fread(buf, 1, sizeof(buf), fp) == 0) {
		fprintf(stderr, "Could not read the file\n");
		fclose(fp);
		return 1;
	}

	disasm(buf, sizeof(buf));

	fclose(fp);
	return 0;
}
