CFLAGS ?= -Wall -Wextra -Wno-switch -O1 -g3

LIB  := libi286dis.a
PROG := i286dis
TEST := test.com
SRCS := dis.c decode.c fmt.c
OBJS := $(SRCS:.c=.o)

.PHONY: all
all: $(LIB) $(PROG) $(TEST)

$(PROG): main.o $(LIB)
	$(CC) $(CFLAGS) $^ -o $@

$(LIB): $(OBJS)
	$(AR) rcs $@ $^

$(TEST): test.asm
	nasm -f bin $^ -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

.PHONY: clean
clean:
	rm -f $(OBJS) $(LIB) $(TEST) $(PROG)
