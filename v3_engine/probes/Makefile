# V3 探针编译 Makefile
CLANG ?= clang
LLVM_STRIP ?= llvm-strip

INCLUDES := -I include
CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_x86 -Wall -Wno-unused-variable

PROBES := tcp_monitor exec_monitor file_access bash_monitor xdp_reporter

.PHONY: all clean

all: $(addsuffix .o, $(PROBES))

%.o: %.c
	$(CLANG) $(CFLAGS) $(INCLUDES) -c $< -o $@
	$(LLVM_STRIP) -g $@

clean:
	rm -f *.o
