# Build the CODAX tracer against the system libbpf (libbpf-dev) and bpftool.
# Non-root: `make`.  Produces bin/codax_tracer. Loading it still needs root.

ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
CLANG ?= clang
BPFTOOL ?= bpftool

BPF_SRC := bpf/codax.bpf.c
BPF_OBJ := build/codax.bpf.o
SKEL    := build/codax.skel.h
APP_SRC := user/codax_tracer.c
APP     := bin/codax_tracer

# Let clang find asm/ and other arch headers the BPF target otherwise misses.
CLANG_SYS_INCLUDES := $(shell $(CLANG) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

.PHONY: all clean
all: $(APP)

build bin:
	mkdir -p $@

# 1) Compile the eBPF C to BPF bytecode (CO-RE object). vmlinux.h comes from local BTF.
$(BPF_OBJ): $(BPF_SRC) bpf/codax.h bpf/vmlinux.h | build
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
		-Ibpf $(CLANG_SYS_INCLUDES) -c $(BPF_SRC) -o $@
	llvm-strip -g $@

# 2) Generate the skeleton header (open/load/attach glue) from the BPF object.
$(SKEL): $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $< > $@

# 3) Compile the userspace loader, linking libbpf.
$(APP): $(APP_SRC) $(SKEL) bpf/codax.h | bin
	$(CC) -g -Wall -Ibuild -Ibpf $(APP_SRC) -lbpf -lelf -lz -o $@

clean:
	rm -rf build bin
