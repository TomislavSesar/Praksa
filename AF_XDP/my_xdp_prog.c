#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/in.h> 

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
    __uint(max_entries, 64);
} xsks_map SEC(".maps");

SEC("xdp")
int xdp_prog(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;                   
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    struct iphdr *iph = (struct iphdr *)((__u8 *)eth + sizeof(struct ethhdr));
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udph = data + sizeof(struct ethhdr) + iph->ihl * 4;
        if ((void *)(udph + 1) > data_end)
            return XDP_PASS;

        __u16 dport = bpf_ntohs(udph->dest);

        if (dport < 10 || dport > 100) {
            bpf_printk("DROP port=%d", dport);
            return XDP_DROP;
        }
        bpf_printk("PASS port=%d", dport);
    }

    bpf_printk("frame received");
    return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, XDP_PASS);
}

char _license[] SEC("license") = "GPL";