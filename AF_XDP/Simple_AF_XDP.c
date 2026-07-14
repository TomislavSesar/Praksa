#include <argp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <xdp/xsk.h>
#include <xdp/libxdp.h>

#define MAX_IFACES 1

/*
    UMEM info
    xsk_ring_prod -> fill queue
    xsk_ring_cons -> collect queue
    *umem -> pointer to umem structure that we don't have full access
    *buffer -> pointer to the beginning of our umem memory
*/
struct xsk_umem_info {
    struct xsk_ring_prod fq;
    struct xsk_ring_cons cq;
    struct xsk_umem *umem;
    void *buffer;
};

/*
    Socket info
    xsk_ring_cons -> rx ring
    xsk_ring_prod -> tx ring
    xsk_umem_info -> structure explained above
    xsk_socket *xsk ->  pointer to our scoket structure
                    that we don't have full access
*/
struct xsk_socket_info {
    struct xsk_ring_cons rx;
    struct xsk_ring_prod tx;
    struct xsk_umem_info *umem;
    struct xsk_socket *xsk;
};

/*
    XDP context
    *ifname -> interface name
    ifindex -> interface number(id)
    xsk_if_queue -> number(id) of channel
    *buffer -> pointer that points to the beginning of the UMEM memory
    xdp_flags -> holds parametrs that control how XDP program is going to attach
    to the interface xsk_bind_flags -> control how XDP socket is going to bind to
    an interface umem_flags -> flags that configure UMEM umem_frames_nr -> number
    of frames in UMEM umem_fill_size -> number of slots in fill_ring where UMEM
    descriptors can be put in umem_comp_size ->   number of slots in
    completion_ring where UMEM descriptors can be put in packet_handler_tid ->
    thread that reads our packets that have arrived to our UMEM or sending them
    packet_handler_thread_started -> bool flag that tells us if our thread is
    activated successfully
        */

struct xdp_eth_context {
    const char *ifname;

    void *buffer;
    struct xsk_socket_info *xsk_socket;
    struct xsk_umem_info *umem;

    uint32_t xdp_flags;
    uint16_t xsk_bind_flags;
    uint32_t umem_flags;

    struct xdp_program *xdp_prog; 

    int ifindex;

    int xsk_if_queue;

    int umem_frames_nr;
    int umem_frame_size;
    int umem_fill_size;
    int umem_comp_size;
    int umem_size;

    int socket_rx_ring_size;
    int socket_tx_ring_size;

    pthread_t packet_handler_tid;
    bool packet_handler_thread_started;
};

static struct xdp_eth_context ctx = {0};

static struct argp_option options[] = {
    {"copy", 'C', 0, 0, "Force XDP copy mode"}, {0}};

struct arguments {
    char *iface;
    int ifaces;
    bool xdp_copy_mode;
};

struct arguments arguments = {0};

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
    switch (key) {
    case ARGP_KEY_ARG:
        if (arguments.ifaces >= MAX_IFACES) {
            printf("There can be maximum %d defined interfaces\n", MAX_IFACES);
            argp_usage(state);
        }
        arguments.iface = arg;
        arguments.ifaces++;
        break;
    case ARGP_KEY_END:
        if (arguments.ifaces < 1) {
            printf("There must be at least one interface defined\n");
            argp_usage(state);
        }
        break;
    case 'C':
        arguments.xdp_copy_mode = true;
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static struct argp argp = {options, parse_opt, NULL, NULL, NULL, NULL, NULL};

static struct xsk_umem_info *xsk_configure_umem(struct xdp_eth_context *ctx)
{
    struct xsk_umem_config umem_cfg = {0};

    // Number of slots in fill ring
    umem_cfg.fill_size = ctx->umem_fill_size;

    // Number of slots in completion ring
    umem_cfg.comp_size = ctx->umem_comp_size;

    // Size of one frame in bytes
    umem_cfg.frame_size = ctx->umem_frame_size;

    // Reserved space on the start of every frame
    umem_cfg.frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM;

    umem_cfg.flags = ctx->umem_flags;

    ctx->umem = (struct xsk_umem_info *)calloc(1, sizeof(struct xsk_umem_info));
    if (ctx->umem == NULL) {
        return NULL;
    }

    /** @brief Creates the UMEM memory region and initializes fill and
     * completion rings. */
    int err = xsk_umem__create(&ctx->umem->umem, ctx->buffer, ctx->umem_size,
                               &ctx->umem->fq, &ctx->umem->cq, &umem_cfg);

    if (err) {
        free(ctx->umem);
        ctx->umem = NULL;
        return NULL;
    }

    ctx->umem->buffer = ctx->buffer;

    return ctx->umem;
}

static void xsk_populate_fill_ring(struct xdp_eth_context *ctx)
{
    int ret, i;
    uint32_t idx = 0;
    struct xsk_umem_info *umem = ctx->umem;

    /** @brief Reserves free slots in fill ring */

    ret = xsk_ring_prod__reserve(&umem->fq, ctx->umem_fill_size, &idx);

    if (ret != ctx->umem_fill_size) {
        printf("%s: xsk_ring_prod__reserve: %d\n", __func__, ret);
        exit(ret);
    }

    for (i = 0; i < ctx->umem_fill_size; i++) {
        /** @brief Saves descriptors that points to free memory chunks in UMEM*/
        *xsk_ring_prod__fill_addr(&umem->fq, idx++) = i * ctx->umem_frame_size;
    }

    /** @brief Tells kernal that umem_fill_size is ready to use*/
    xsk_ring_prod__submit(&umem->fq, ctx->umem_fill_size);
}

static struct xsk_socket_info *xsk_configure_socket(struct xdp_eth_context *ctx)
{

    struct xsk_socket_config cfg = {0};
    struct xsk_socket_info *xsk;
    int ret;

    xsk = (struct xsk_socket_info *)calloc(1, sizeof(*xsk));
    if (!xsk) {
        exit(errno);
    }

    xsk->umem = ctx->umem;
    cfg.xdp_flags = ctx->xdp_flags;
    cfg.bind_flags = ctx->xsk_bind_flags;
    cfg.libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD;
    cfg.rx_size = ctx->socket_rx_ring_size;
    cfg.tx_size = ctx->socket_tx_ring_size;

    ret = xsk_socket__create(&xsk->xsk, ctx->ifname, ctx->xsk_if_queue,
                             ctx->umem->umem, &xsk->rx, NULL, &cfg);

    if (ret) {
        printf("%s: Failed xsk_socket__create (%d)\n", ctx->ifname, ret);
        free(xsk);
        return NULL;
    }

    return xsk;
}

static void print_packet(uint8_t *pkt, uint32_t len)
{

    static int counter = 0;
    counter++;

    const char *protocol = "#";
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    char src_mac[18];
    char dst_mac[18];

    const struct ether_header *eth = (const struct ether_header *)(pkt);

    if (len <= sizeof(struct ether_header)) {
        fprintf(stderr, "Packet too short");
        return;
    }

    strncpy(src_mac, ether_ntoa((const struct ether_addr *)eth->ether_shost),
            18);
    strncpy(dst_mac, ether_ntoa((const struct ether_addr *)eth->ether_dhost),
            18);
    src_mac[17] = '\0';
    dst_mac[17] = '\0';

    const struct iphdr *ip =
        (const struct iphdr *)(pkt + sizeof(struct ether_header));

    switch (ip->protocol) {
    case IPPROTO_UDP:
        protocol = "UDP";
        break;
    case IPPROTO_TCP:
        protocol = "TCP";
        break;
    default:
        break;
    }

    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];

    struct in_addr addr;

    addr.s_addr = ip->saddr;
    strncpy(src_ip, inet_ntoa(addr), INET_ADDRSTRLEN);

    addr.s_addr = ip->daddr;
    strncpy(dst_ip, inet_ntoa(addr), INET_ADDRSTRLEN);

    if (ip->protocol == IPPROTO_TCP) {
        const struct tcphdr *tcph =
            (const struct tcphdr *)(pkt + sizeof(struct ether_header) +
                                    ip->ihl * 4);
        src_port = ntohs(tcph->source);
        dst_port = ntohs(tcph->dest);
    }

    else if (ip->protocol == IPPROTO_UDP) {
        const struct udphdr *udph =
            (const struct udphdr *)(pkt + sizeof(struct ether_header) +
                                    ip->ihl * 4);
        src_port = ntohs(udph->source);
        dst_port = ntohs(udph->dest);
    }

    if (strcmp(protocol, "#") == 0) {
        printf("%d: %s -> %s; 0x%02x; %s: %d -> %s: %d\n", counter, src_mac,
               dst_mac, ip->protocol, src_ip, src_port, dst_ip, dst_port);
    }

    else {
        printf("%d: %s -> %s; %s; %s: %d -> %s: %d\n", counter, src_mac,
               dst_mac, protocol, src_ip, src_port, dst_ip, dst_port);
    }
}

static int handle_receive_packets(struct xsk_socket_info *xsk,
                                  struct xdp_eth_context *ctx)
{

    unsigned int rcvd, i;
    uint32_t idx_rx = 0, idx_fq = 0;
    int ret;

    /** @brief checks if there are new packets in RX ring without syscall*/

    rcvd = xsk_ring_cons__peek(&xsk->rx, 32, &idx_rx);

    // checks if there is enough spaces
    if (!rcvd) {
        return 0;
    }

    /** @brief Reserves free space in producer ring (in this case fill ring) */
    ret = xsk_ring_prod__reserve(&xsk->umem->fq, rcvd, &idx_fq);
    if (ret != (int)rcvd) {
        printf("%s: Warning: xsk_ring_prod__reserve, asked %d, got %d\n",
               ctx->ifname, rcvd, ret);
    }

    for (i = 0; i < rcvd; i++) {

        /** @brief Returns descriptor in rx ring*/
        const struct xdp_desc *desc =
            xsk_ring_cons__rx_desc(&xsk->rx, idx_rx++);
        print_packet(
            (uint8_t *)xsk_umem__get_data(xsk->umem->buffer, desc->addr),
            desc->len);
        *xsk_ring_prod__fill_addr(&xsk->umem->fq, idx_fq++) = desc->addr;
    }

    /** @brief Moves pointer in fill ring for rcvd spaces */
    xsk_ring_prod__submit(&xsk->umem->fq, rcvd);

    /** @brief Moves consumer pointer in RX ring for rcvd spaces */
    xsk_ring_cons__release(&xsk->rx, rcvd);

    return rcvd;
}

static void *rx_thread(void *args)
{
    struct xdp_eth_context *ctx = (struct xdp_eth_context *)args;
    struct xsk_socket_info *xsk_socket = ctx->xsk_socket;
    struct pollfd fds = {0};
    int ret;
    int processed_frames = 0;

    fds.fd = xsk_socket__fd(xsk_socket->xsk);
    fds.events = POLLIN;
    while (true) {
        ret = poll(&fds, 1, -1);
        if (ret == 1) {
            processed_frames = handle_receive_packets(xsk_socket, ctx);
            if (processed_frames == 0) {
                printf("There were no frames to process\n");
            }
        } else if (ret == -1) {
            if (errno != EINTR) {
                perror("poll:");
                break;
            }
        }
    }

    return NULL;
}

static void tear_down(int reason)
{
    void *status = 0;
    int err;

    (void)reason;

    printf("%s: Tear down\n", __func__);

    if (ctx.packet_handler_thread_started) {
        printf("%s: pthread_cancel\n", __func__);
        ctx.packet_handler_thread_started = false;
        err = pthread_cancel(ctx.packet_handler_tid);
        if (err != 0 && err != ESRCH) {
            printf("%s: packet handler thread cancelation failed, %s\n",
                   ctx.ifname, strerror(err));
        }

        err = pthread_join(ctx.packet_handler_tid, &status);
        if (err != 0 && err != ESRCH) {
            printf("%s: packet handler thread cancelation failed, %s\n",
                   ctx.ifname, strerror(err));
        }
        if (status != PTHREAD_CANCELED) {
            printf("%s: packet handler thread did not join with canceled, %d\n",
                   ctx.ifname, status ? *(int *)status : 0);
        }
    }

    if (ctx.xdp_prog != NULL) {
        xdp_program__detach(ctx.xdp_prog, ctx.ifindex, XDP_MODE_SKB, 0);
        xdp_program__close(ctx.xdp_prog);
        ctx.xdp_prog = NULL;
    }

    if (ctx.xsk_socket != NULL && ctx.xsk_socket->xsk != NULL) {
        printf("%s: xsk_socket__delete\n", __func__);
        xsk_socket__delete(ctx.xsk_socket->xsk);
        free(ctx.xsk_socket);
        ctx.xsk_socket = NULL;
    }
    if (ctx.umem != NULL && ctx.umem->umem != NULL) {
        printf("%s: xsk_umem__delete\n", __func__);
        err = xsk_umem__delete(ctx.umem->umem);
        if (err) {
            printf("%s: xsk_umem_delete failed with %d\n", ctx.ifname, err);
        }
        free(ctx.umem);
        ctx.umem = NULL;
    }

    if (ctx.buffer != NULL) {
        free(ctx.buffer);
        ctx.buffer = NULL;
    }
}

static void exit_application(int signal)
{
    printf("Exiting with signal %d\n", signal);
    tear_down(0);
    exit(0);
}

int main(int argc, char **argv)
{
    int err = 0;
    int cntr = 0;

    argp_parse(&argp, argc, argv, 0, NULL, &arguments);

    ctx.xdp_flags = XDP_FLAGS_SKB_MODE;
    ctx.xsk_bind_flags = XDP_COPY;

    ctx.ifname = arguments.iface;
    ctx.socket_rx_ring_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
    ctx.socket_tx_ring_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
    ctx.umem_frame_size = XSK_UMEM__DEFAULT_FRAME_SIZE;
    ctx.umem_fill_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
    ctx.umem_comp_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
    ctx.umem_frames_nr = ctx.umem_fill_size + ctx.umem_comp_size;
    ctx.umem_size = ctx.umem_frames_nr * ctx.umem_frame_size;
    ctx.xsk_if_queue = 0;

    ctx.ifindex = if_nametoindex(ctx.ifname);
    if (ctx.ifindex == 0) {
        printf("%s: Failed to get ifindex: %s\n", ctx.ifname, strerror(errno));
        exit_application(0);
    }
    if (posix_memalign(&ctx.buffer, getpagesize(), ctx.umem_size)) {
        printf("%s: ERROR: Can't allocate buffer memory \"%s\"\n", ctx.ifname,
               strerror(errno));
        exit_application(0);
    }

    ctx.umem = xsk_configure_umem(&ctx);
    if (ctx.umem == NULL) {
        printf("%s: ERROR: Can't create umem \"%s\"\n", ctx.ifname,
               strerror(errno));
        exit_application(0);
    }
    xsk_populate_fill_ring(&ctx);

    ctx.xsk_socket = xsk_configure_socket(&ctx);
    if (ctx.xsk_socket == NULL) {
        printf("%s: ERROR: Can't setup AF_XDP socket \"%s\"\n", ctx.ifname,
               strerror(errno));
        exit_application(0);
    }

    ctx.xdp_prog = xdp_program__open_file("my_xdp_prog.o", NULL, NULL);
    if (!ctx.xdp_prog) {
        printf("Failed to open XDP program\n");
        exit_application(0);
    }

    err = xdp_program__attach(ctx.xdp_prog, ctx.ifindex, XDP_MODE_SKB, 0);
    if (err) {
        printf("Failed to attach XDP program: %d\n", err);
        exit_application(0);
    }

    int map_fd = bpf_map__fd(bpf_object__find_map_by_name(
                xdp_program__bpf_obj(ctx.xdp_prog), "xsks_map"));
    xsk_socket__update_xskmap(ctx.xsk_socket->xsk, map_fd);

    err = pthread_create(&ctx.packet_handler_tid, NULL, rx_thread, &ctx);
    if (err) {
        printf("%s: Failed to start handler thread, %s\n", ctx.ifname,
               strerror(err));
        exit_application(0);
    }
    ctx.packet_handler_thread_started = true;

    printf("Initialized, ready to receieve\n");

    pthread_join(ctx.packet_handler_tid, NULL);

    exit(1);
}