#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>


struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
    __uint(max_entries, 64);
} xsks_map SEC(".maps");

SEC("xdp")

int xdp_prog(struct xdp_md *ctx) {
    
    bpf_printk("%d. frame recvied");

    return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, XDP_PASS);
}

char _license[] SEC("license") = "GPL";