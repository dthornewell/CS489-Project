CC = gcc
CFLAGS = -Wall -Wextra -O3

SRC = $(wildcard *.c)
TARGETS = $(SRC:.c=)

all: $(TARGETS)

%: %.c
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm $(TARGETS)
