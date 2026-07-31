#include "hook.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <linux/udp.h>

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 5);
} xdpcap_hook SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 64);
} xsks_map SEC(".maps");

SEC("xdp")
int xdp_prog(struct xdp_md *ctx)
{
    long ret = bpf_redirect_map(&xsks_map, ctx->rx_queue_index, XDP_PASS);
    if (ret == XDP_REDIRECT) {
        return xdpcap_exit(ctx, &xdpcap_hook, XDP_REDIRECT);
    }
    return xdpcap_exit(ctx, &xdpcap_hook, XDP_PASS);
}
