CLANG ?= clang
CC ?= gcc
BPFTOOL ?= bpftool

BUILD_DIR := build
EBPF_DIR := ebpf
USER_DIR := userspace
INCLUDE_DIR := include

AI_DIR := ai-engine/runtime

# eBPF programs
BPF_SRC := $(EBPF_DIR)/lsm_sensor.bpf.c
BPF_OBJ := $(BUILD_DIR)/lsm_sensor.bpf.o
SKEL := $(BUILD_DIR)/lsm_sensor.skel.h

NETWORK_BPF_SRC := $(EBPF_DIR)/network_sensor.bpf.c
NETWORK_BPF_OBJ := $(BUILD_DIR)/network_sensor.bpf.o
NETWORK_SKEL := $(BUILD_DIR)/network_sensor.skel.h

# Userspace binary
USER_BIN := $(BUILD_DIR)/loader

# vmlinux header
VMLINUX := $(INCLUDE_DIR)/vmlinux.h

# Compiler flags
BPF_CFLAGS := -O2 -g -target bpf -I$(INCLUDE_DIR)

USER_CFLAGS := -O2 -g -Wall \
	-I$(INCLUDE_DIR) \
	-I$(BUILD_DIR) \
	-I$(AI_DIR)

# 🔥 LITE VERSION (NO BACKENDS)
$(info [*] Building BPFense Lite (no external AI backends))

# Userspace sources (CLEAN)
USER_SRC := \
	userspace/loader.c \
	userspace/container_pod_resolver.c \
	userspace/rule_engine.c \
	userspace/feature_extractor.c \
	userspace/decision_engine.c \
	userspace/response_engine.c \
	userspace/agent_engine.c \
	userspace/model_verify.c \
	$(AI_DIR)/ai_engine.c

LIBS := -lbpf -lelf -lpthread -lssl -lcrypto

.PHONY: all clean

# Build everything
all: $(BPF_OBJ) $(SKEL) $(NETWORK_BPF_OBJ) $(NETWORK_SKEL) $(USER_BIN)

# Create build directory
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Generate vmlinux.h
$(VMLINUX):
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX)

# Compile LSM eBPF program
$(BPF_OBJ): $(BPF_SRC) $(VMLINUX) | $(BUILD_DIR)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

# Generate skeleton
$(SKEL): $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $< > $@

# Compile Network eBPF program
$(NETWORK_BPF_OBJ): $(NETWORK_BPF_SRC) $(VMLINUX) | $(BUILD_DIR)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

# Generate network skeleton
$(NETWORK_SKEL): $(NETWORK_BPF_OBJ)
	$(BPFTOOL) gen skeleton $< > $@

# Build userspace loader
$(USER_BIN): $(USER_SRC) $(SKEL) $(NETWORK_SKEL)
	$(CC) $(USER_CFLAGS) $(USER_SRC) -o $@ $(LIBS)

# Clean
clean:
	rm -rf build
	rm -f include/vmlinux.h
