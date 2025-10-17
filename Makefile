CFLAGS ?= -Wall -Wextra -Wno-switch -O1

LIB := libi286dis.a
SRCS := dis.c
OBJS := $(SRCS:.c=.o)

.PHONY: all
all: $(LIB) test

$(LIB): $(OBJS)
	$(AR) rcs $@ $^

test: test.o $(LIB)
	$(CC) $(CFLAGS) $^ -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

.PHONY: clean
clean:
	rm -f $(OBJS) $(LIB) test
