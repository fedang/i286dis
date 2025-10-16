#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>

struct instr {
	uint16_t addr;
	uint8_t length;
	uint8_t opcode;
};

int decode(uint8_t *bytes, size_t len, int *branch)
{
	size_t idx = 0;
	*branch = 0;

	switch (bytes[idx++]) {
		case 0xF8:
			printf("CLC\n");
			break;

		case 0xFA:
			printf("CLI\n");
			break;

		case 0xFC:
			printf("CLD\n");
			break;

		case 0xE9: {
			int16_t target = bytes[idx++] | (bytes[idx++] << 8);
			*branch = target;
			printf("jmp near %hx\n", target);
			break;
		}

		case 0xEA: {
			int16_t target = bytes[idx++] | (bytes[idx++] << 8);
			uint16_t segment = bytes[idx++] | (bytes[idx++] << 8);
			printf("jmp far %hx:%hx\n", segment, target);
			break;
		}

		case 0xEB: {
			int8_t target = bytes[idx++];
			*branch = target;
			printf("jmp short %hhx\n", target);
			break;
		}

		default:
			printf("UNKNOWN\n");
			return -1;
	}

	return idx;
}

#define QUEUE_LEN 256

struct queue {
	int data[QUEUE_LEN];
	size_t head;
	size_t tail;
	size_t used;
	size_t size;
};

void queue_init(struct queue *q)
{
	memset(q, 0, sizeof(struct queue));
}

bool queue_empty(struct queue *q)
{
	return q->used == 0;
}

bool queue_full(struct queue *q)
{
	return q->used == QUEUE_LEN;
}

bool queue_put(struct queue *q, int data)
{
	if (queue_full(q))
		return false;

	q->data[q->tail] = data;
	q->tail = (q->tail + 1) % QUEUE_LEN;
	q->used++;
	return true;
}

bool queue_get(struct queue *q, int *data)
{
	if (queue_empty(q))
		return false;

	*data = q->data[q->head];
	q->head = (q->head + 1) % QUEUE_LEN;
	q->used--;
	return true;
}

void disasm(uint8_t *bytes, size_t size)
{
	struct queue q;
	queue_init(&q);

	queue_put(&q, 0);

	while (!queue_empty(&q)) {
		int addr;
		queue_get(&q, &addr);

		while (addr < size) {
			int branch;
			int op = decode(bytes + addr, size - addr, &branch);
			if (op < 0)
				break;

			addr += op;
			if (branch)
				queue_put(&q, addr + branch);
		}
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

