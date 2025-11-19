#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <unistd.h>

#include "i286dis.h"

static unsigned base = 0x100;
static unsigned entry = 0x100;

void disasm(uint8_t *bytes, size_t len)
{
    struct dis dis;
    dis_init(&dis, bytes, len, base);
    dis_push_entry(&dis, entry);
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

        insn_format(buf + off, sizeof(buf) - off, ins, FMT_DEFAULT);
        printf("\t\t\t%s\n", buf);
    }

    dis_deinit(&dis);
}

#define usage(x) \
    fprintf(stderr, "Usage: %s [-b BASE] [-e ENTRY] FILE\n", x);

int main(int argc, char **argv)
{
    int opt;

    while ((opt = getopt(argc, argv, "b:e:")) != -1) {
        switch (opt) {
            case 'b':
                base = strtol(optarg, NULL, 0);
                entry = base;
                break;
            case 'e':
                entry = strtol(optarg, NULL, 0);
                break;
            default:
                usage(argv[0]);
                return 1;
        }
    }

	if (optind != argc - 1) {
		usage(argv[0]);
		return 1;
	}

	FILE *fp = fopen(argv[optind], "rb");
	if (!fp) {
		perror("Failed to open file");
		return 1;
	}

    if (fseek(fp, 0, SEEK_END) < 0) {
        perror("Failed to seek");
        return 1;
    }

    size_t size = ftell(fp);
    rewind(fp);

	uint8_t *buf = malloc(size);
    if (!buf) {
        perror("Failed to allocate");
        return 1;
    }

    size_t len = fread(buf, 1, size, fp);
	if (len != size) {
		fprintf(stderr, "Could not read the file\n");
		fclose(fp);
		return 1;
	}

	fclose(fp);
	disasm(buf, size);
    free(buf);
	return 0;
}
