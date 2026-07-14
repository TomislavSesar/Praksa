#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

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

    struct ether_header *eth = data;

    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }

    struct iphdr *iph =
        (struct iphdr *)((uint8_t *)eth + sizeof(struct ether_header));

    if ((void *)(iph + 1) > data_end) {
        return XDP_PASS;
    }

    if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udph = data + sizeof(struct ether_header) + iph->ihl * 4;
        if ((void *)(udph + 1) > data_end)
            return XDP_PASS;

        __u16 dport = bpf_ntohs(udph->dest);

        if (dport < 10 || dport > 100) {
            bpf_printk("DROP port=%d", udph->dest);
            bpf_printk("DROP port_nthos=%d", ntohs(udph->dest));
            return XDP_DROP;
        }
        bpf_printk("PASS port=%d", udph->dest);
        bpf_printk("PASS port_nthos=%d", ntohs(udph->dest));
    }

    bpf_printk("frame recvied");

    return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, XDP_PASS);
}

char _license[] SEC("license") = "GPL";