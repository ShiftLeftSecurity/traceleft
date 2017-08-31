CLANG?=clang
LLC?=llc
SHELL=/bin/bash -o pipefail
DEST_DIR?=/dist
LINUX_HEADERS?=$(shell cat /usr/src/kernel-package.txt)

.PHONY: all

all: $(addprefix $(DEST_DIR)/, $(addsuffix .bpf, $(basename $(wildcard *.c))))

$(DEST_DIR)/%.bpf: %.c
	@mkdir -p "$(DEST_DIR)"
	$(CLANG) -D__KERNEL__ -D__ASM_SYSREG_H \
		-DCIRCLE_BUILD_URL=\"$(CIRCLE_BUILD_URL)\" \
		-Wno-unused-value \
		-Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types \
		-Wunused \
		-Wall \
		-Werror \
		-O2 -emit-llvm -c $< \
		$(foreach path,$(LINUX_HEADERS), -I $(path)/arch/x86/include -I $(path)/arch/x86/include/generated -I $(path)/include -I $(path)/include/generated/uapi -I $(path)/arch/x86/include/uapi -I $(path)/include/uapi) \
		-o - | $(LLC) -march=bpf -filetype=obj -o $@
