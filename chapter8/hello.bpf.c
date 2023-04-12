#include <linux/types.h>
#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "packet.h"

SEC("xdp")
int ping(struct xdp_md *ctx) {
    long protocol = lookup_protocol(ctx);
    if (protocol == 1) // ICMP 
    {
        //bpf_printk("Hello ping received\n");
        bpf_printk("Hello ping dropped\n");
        return XDP_DROP; 
    }
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
