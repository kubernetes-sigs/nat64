include ../Makefile.defs

BPF = nat64.o

include ./Makefile.bpf

.PHONY: all bpf_all build_all clean

all: bpf_all

bpf_all: $(BPF)

build_all: force
	$(MAKE) bpf_all

clean:
	rm -f *.o *.ll *.i *.s
