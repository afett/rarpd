TARGET=rarpd

CFLAGS=-std=c99 -pedantic -g -O0 -Wall -Werror
CPPFLAGS=-D_GNU_SOURCE
LDFLAGS=

SRC=$(wildcard *.c)
OBJ=$(SRC:%.c=%.o)

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $^ -o $@

clean:
	rm -rf  $(TARGET) $(OBJ)

.PHONY: all clean


