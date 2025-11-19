#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <unistd.h>

#include "i286dis.h"

static unsigned base = 0x100;
static unsigned entry = 0x100;

#define SPACING 32

int yellow(char *buf, size_t size, struct insn *ins)
{
    (void)ins;
    return snprintf(buf, size, "\e[93m");
}

int reset(char *buf, size_t size, struct insn *ins)
{
    (void)ins;
    return snprintf(buf, size, "\e[0m");
}

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

    struct fmt fmt;
    fmt_init(&fmt, FMT_DEFAULT);
    fmt.opcode_pre = yellow;
    fmt.opcode_post = reset;

    while (dis_iterate(&dis, &idx, &ins)) {
        if (!ins) {
            uint8_t byte = bytes[idx - 1];
            int space = printf("%x: %02hhx", idx + dis.base - 1, byte);

            for (int i = space; i < SPACING; i++)
                putchar(' ');

            if (isprint(byte))
                printf("db '%c'\n", byte);
            else
                printf("db '\\x%hhx'\n", byte);
            continue;
        }

        int space = printf("%x:", ins->addr);
        off = 0;

        //while (insn_is_prefix(ins)) {
        //    space += printf(" %02x", bytes[idx - 1]);

        //    off += snprintf(buf + off, sizeof(buf) - off, "%s ", opcode_mnemonics[ins->op]);

        //    if (!dis_iterate(&dis, &idx, &ins) || !ins)
        //        break;
        //}

        for (int i = 0; i < ins->len; i++)
            space += printf(" %02x", bytes[idx - ins->len + i]);

        fmt_insn(&fmt, ins, buf + off, sizeof(buf) - off);

        for (int i = space; i < SPACING; i++)
            putchar(' ');

        printf("%s\n", buf);
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
