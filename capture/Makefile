# Sigil C Capture Engine Makefile
CC ?= clang
CFLAGS ?= -O3 -Wall -Wextra -pedantic -std=c11 -Iinclude -D_GNU_SOURCE
LDFLAGS ?= -pthread

BUILD_DIR ?= build
SRC_DIR = src
TEST_DIR = tests

SRCS = $(SRC_DIR)/sigil_ring.c $(SRC_DIR)/sigil_shm.c $(SRC_DIR)/sigil_pcap_fast.c $(SRC_DIR)/sigil_capture.c
OBJS = $(patsubst $(SRC_DIR)/%.c, $(BUILD_DIR)/%.o, $(SRCS))

TARGET = $(BUILD_DIR)/sigil-capture
TEST_RING = $(BUILD_DIR)/test_ring
TEST_PCAP = $(BUILD_DIR)/test_pcap_fast

.PHONY: all test clean

all: $(TARGET) $(TEST_RING) $(TEST_PCAP)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET): $(OBJS) $(BUILD_DIR)/main.o
	$(CC) $(OBJS) $(BUILD_DIR)/main.o -o $@ $(LDFLAGS)

$(BUILD_DIR)/main.o: $(SRC_DIR)/main.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(TEST_RING): $(OBJS) $(TEST_DIR)/test_ring.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(OBJS) $(TEST_DIR)/test_ring.c -o $@ $(LDFLAGS)

$(TEST_PCAP): $(OBJS) $(TEST_DIR)/test_pcap_fast.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(OBJS) $(TEST_DIR)/test_pcap_fast.c -o $@ $(LDFLAGS)

test: $(TEST_RING) $(TEST_PCAP)
	@echo "=== Running C Ring Test ==="
	@./$(TEST_RING)
	@echo "=== Running C PCAP Fast Test ==="
	@./$(TEST_PCAP)
	@echo "All C tests passed successfully."

clean:
	rm -rf $(BUILD_DIR)
