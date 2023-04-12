TARGET = hello
ARCH = $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

BPF_OBJ = ${TARGET:=.bpf.o}

all: $(TARGET) $(BPF_OBJ) 
.PHONY: all 
.PHONY: $(TARGET)

$(TARGET): $(BPF_OBJ)
	sudo bpftool net detach xdp dev lo
	sudo rm -f /sys/fs/bpf/$(TARGET)
	sudo bpftool prog load $(BPF_OBJ) /sys/fs/bpf/$(TARGET)
	sudo bpftool net attach xdp pinned /sys/fs/bpf/$(TARGET) dev lo

$(BPF_OBJ): %.o: %.c vmlinux.h
	clang \
	    -target bpf \
	    -D __BPF_TRACING__ \
		-I/usr/include/$(shell uname -m)-linux-gnu \
	    -Wall \
	    -O2 -o $@ -c $<

vmlinux.h:
	sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h		

clean:
	- sudo bpftool net detach xdp dev lo
	#- sudo bpftool net detach xdp dev docker0
	- sudo rm -f /sys/fs/bpf/$(TARGET)
	- sudo rm -f $(BPF_OBJ)
	#- sudo tc filter delete dev docker0 parent ffff:

