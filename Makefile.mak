# Makefile
CC = gcc
CFLAGS = -std=c23 -Wall -Wextra -pthread
LDFLAGS =
SOURCES = main.c config.c
OBJECTS = $(SOURCES:.c=.o)
EXECUTABLE = reverse_proxy

all: $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(CFLAGS) $(OBJECTS) -o $@ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJECTS) $(EXECUTABLE)

.PHONY: all clean