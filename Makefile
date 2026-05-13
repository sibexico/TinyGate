PROJECT := tinygate
OUT_DIR := build

SRCS := main.c config.c http_parser.c
TEST_SRCS := tests.c config.c http_parser.c

CFLAGS_COMMON ?= -std=c23 -O3 -Wall -Wextra -pedantic
CFLAGS_TEST ?= -std=c23 -O2 -Wall -Wextra -pedantic

LDFLAGS_POSIX ?= -pthread -lssl -lcrypto
LDFLAGS_WINDOWS ?= -lws2_32 -lssl -lcrypto

CC_NATIVE ?= gcc
CC_LINUX_X86_64 ?= gcc
CC_LINUX_ARM64 ?= aarch64-linux-gnu-gcc
CC_WINDOWS_X86_64 ?= x86_64-w64-mingw32-gcc
CC_WINDOWS_ARM64 ?= aarch64-w64-mingw32-gcc
CC_FREEBSD_X86_64 ?= cc

.PHONY: all native test linux-x86_64 linux-arm64 windows-x86_64 windows-arm64 freebsd-x86_64 clean

all: native

native:
	$(CC_NATIVE) $(CFLAGS_COMMON) $(SRCS) -o $(PROJECT) $(LDFLAGS_POSIX)

test:
	$(CC_NATIVE) $(CFLAGS_TEST) $(TEST_SRCS) -o $(PROJECT)_tests $(LDFLAGS_POSIX)
	./$(PROJECT)_tests

linux-x86_64: $(OUT_DIR)/$(PROJECT)-linux-x86_64

linux-arm64: $(OUT_DIR)/$(PROJECT)-linux-arm64

windows-x86_64: $(OUT_DIR)/$(PROJECT)-windows-x86_64.exe

windows-arm64: $(OUT_DIR)/$(PROJECT)-windows-arm64.exe

freebsd-x86_64: $(OUT_DIR)/$(PROJECT)-freebsd-x86_64

$(OUT_DIR):
	mkdir -p $(OUT_DIR)

$(OUT_DIR)/$(PROJECT)-linux-x86_64: $(SRCS) | $(OUT_DIR)
	$(CC_LINUX_X86_64) $(CFLAGS_COMMON) $(SRCS) -o $@ $(LDFLAGS_POSIX)

$(OUT_DIR)/$(PROJECT)-linux-arm64: $(SRCS) | $(OUT_DIR)
	@if command -v $(CC_LINUX_ARM64) >/dev/null 2>&1; then \
		$(CC_LINUX_ARM64) $(CFLAGS_COMMON) $(SRCS) -o $@ $(LDFLAGS_POSIX); \
	else \
		echo "Skipping $@: $(CC_LINUX_ARM64) not found"; \
	fi

$(OUT_DIR)/$(PROJECT)-windows-x86_64.exe: $(SRCS) | $(OUT_DIR)
	$(CC_WINDOWS_X86_64) $(CFLAGS_COMMON) $(SRCS) -o $@ $(LDFLAGS_WINDOWS)

$(OUT_DIR)/$(PROJECT)-windows-arm64.exe: $(SRCS) | $(OUT_DIR)
	@if command -v $(CC_WINDOWS_ARM64) >/dev/null 2>&1; then \
		$(CC_WINDOWS_ARM64) $(CFLAGS_COMMON) $(SRCS) -o $@ $(LDFLAGS_WINDOWS); \
	else \
		echo "Skipping $@: $(CC_WINDOWS_ARM64) not found"; \
	fi

$(OUT_DIR)/$(PROJECT)-freebsd-x86_64: $(SRCS) | $(OUT_DIR)
	$(CC_FREEBSD_X86_64) $(CFLAGS_COMMON) $(SRCS) -o $@ $(LDFLAGS_POSIX)

clean:
	rm -rf $(OUT_DIR) $(PROJECT) $(PROJECT)_tests
