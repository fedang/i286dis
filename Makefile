CFLAGS ?= -Wall -Wextra -Wno-switch -O1

LIB  := libi286dis.a
TEST := test test.com
SRCS := dis.c
OBJS := $(SRCS:.c=.o)

.PHONY: all
all: $(LIB) $(TEST)

$(LIB): $(OBJS)
	$(AR) rcs $@ $^

test: test.o $(LIB)
	$(CC) $(CFLAGS) $^ -o $@

test.com: test.asm
	nasm -f bin $^ -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

.PHONY: clean
clean:
	rm -f $(OBJS) $(LIB) test
