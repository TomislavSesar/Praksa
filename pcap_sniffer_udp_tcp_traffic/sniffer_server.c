// sniffer_server.c
#include <argp.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ETH_LENGHT 14

static struct argp_option options[] = {
    {"interface", 'i', "string", 0,
     "This argument sets up the interface where our traffic is going to be "
     "sniffed"},
    {"filter", 'f', "string", 0,
     "This argument sets up the filter by which our traffic is going to be "
     "filtered"},
    {0}};

struct arguments {
    char *interface;
    char *filter;
};

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{

    struct arguments *arguments = state->input;

    switch (key) {
    case 'i':
        arguments->interface = arg;
        break;
    case 'f':
        arguments->filter = arg;
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static struct argp argp = {options, parse_opt, NULL, NULL, NULL, NULL, NULL};

void packet_processing(u_char *args, const struct pcap_pkthdr *header,
                       const u_char *packet)
{
    char *protocol = "#";
    // char *src_ip;
    // char *dst_ip;
    __be16 src_port;
    __be16 dst_port;
    int *counter = (int *)args;
    char src_mac[18];
    char dst_mac[18];

    // Counting packets

    (*counter)++;

    // ETH header

    /* Packet's first header is eth header that contains source and destination
    mac address
    ether_header structure contains: uint8_t ether_dhost(dst_mac), uint8_t
    ether_shost(src_mac), uint16_t ether type*/
    const struct ether_header *eth = (const struct ether_header *)packet;

    // Checking if eth header is long enough
    if (header->caplen <= ETH_LENGHT) {
        fprintf(stderr, "Packet too short");
        return;
    }

    /* ether_shost, ether_dhost need to be cast because function ether_ntoa
    only accepts ether_addr structure, ether_ntoa turns raw bytes into
    readable mac address */
    strncpy(src_mac, ether_ntoa((struct ether_addr *)eth->ether_shost), 18);
    strncpy(dst_mac, ether_ntoa((struct ether_addr *)eth->ether_dhost), 18);

    // IP header

    /* iphdr contains
    ihl = Internet Header length
    version = IP version(always 4)
    tos = Type of service, how packet is going to be handled
    tot_len = total length of packet
    id = when payload is fragmented, what is position of our packet
    frag_off = fragment offset
    ttl = time to live
    protocol
    check = header check sum
    saddr = source ip
    daddr = destination ip
    */
    const struct iphdr *ip = (const struct iphdr *)(packet + ETH_LENGHT);

    // Checking which protocol is used
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

    // Helper structure that is storing ip address and with function inet_ntoa,
    // turning bytes into IP address form

    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];

    struct in_addr addr;

    addr.s_addr = ip->saddr;
    strncpy(src_ip, inet_ntoa(addr), INET_ADDRSTRLEN);

    addr.s_addr = ip->daddr;
    strncpy(dst_ip, inet_ntoa(addr), INET_ADDRSTRLEN);

    // If we want to know what port our traffic is going to, first we need to
    // know which protocol is processing our traffic

    // Length of ETH header is fixed = 14, but length of IP can vary from 20 to
    // 60 bytes, for that reason we need to use ip->ihl which tells us ip header
    // length and multiply it with 4 to get true size in bytes

    // TCP header

    if (ip->protocol == IPPROTO_TCP) {
        const struct tcphdr *tcph =
            (const struct tcphdr *)(packet + ETH_LENGHT + ip->ihl * 4);
        src_port = ntohs(tcph->source);
        dst_port = ntohs(tcph->dest);
    }

    // UDP header

    else if (ip->protocol == IPPROTO_UDP) {
        const struct udphdr *udph =
            (const struct udphdr *)(packet + ETH_LENGHT + ip->ihl * 4);
        src_port = ntohs(udph->source);
        dst_port = ntohs(udph->dest);
    }

    if (protocol == "#") {
        printf("%d: %s -> %s; 0x%02x; %s: %d -> %s: %d\n", *counter, src_mac,
               dst_mac, ip->protocol, src_ip, src_port, dst_ip, dst_port);
    } else {
        printf("%d: %s -> %s; %s; %s: %d -> %s: %d\n", *counter, src_mac,
               dst_mac, protocol, src_ip, src_port, dst_ip, dst_port);
    }
}

int main(int argc, char *argv[])
{

    struct arguments arguments;

    arguments.interface = "";
    arguments.filter = "";

    argp_parse(&argp, argc, argv, 0, 0, &arguments);

    if (strcmp(arguments.interface, "") == 0) {
        fprintf(stderr, "Interface nije definiran\n");
        return 1;
    }
    if (strcmp(arguments.filter, "") == 0) {
        fprintf(stderr, "Filter nije definiran\n");
        return 1;
    }

    // Interface that we are going to sniff (eth0)
    char *device = arguments.interface;

    // Filter string that is needed for pcap filter
    char *filter_string = arguments.filter;

    // Session handle (something like id)
    pcap_t *handle;

    /* Buffer (string) that contains our error
    message if there is any */
    char errbuf[PCAP_ERRBUF_SIZE];

    // Contains our compiled filter
    struct bpf_program bf;

    // Netmask of device that is sniffing
    bpf_u_int32 mask;

    // IP address of our sniffing device
    bpf_u_int32 net;

    /* Metadata about our packet (time, number of
    captured bytes, real packet size) */
    struct pcap_pkthdr header;

    /* Packet, it is u_char type because our packet is
    just a stream of bytes */
    const u_char *packet;

    // Counter for counting our packets
    int counter = 0;

    // Initializing our device that is going to be sniffing

    if (pcap_lookupnet(device, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Interface doesn't exist %s: %s\n", device, errbuf);
        return 2;
    }

    // Opening session

    /* device = interface, BUFSIZ = max bytes per packet,
    1 = promiscuous mode, 1000 = timeout how long does it wait for packet,
    errbuf = string that stores error
    setting session id */
    handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", device, errbuf);
        return (2);
    }

    /* pcap_compile puts bytecode bpf instructions generated modeled by our
       filter string in bpf_program structure which contains
       bf_len-> number of BPF instructions and
       bf_insns-> holds our instructions */
    if (pcap_compile(handle, &bf, filter_string, 0, mask)) {
        fprintf(stderr, "Couldn't parse the filter %s\n", pcap_geterr(handle));
        return (2);
    }

    /* pcap_setfilter sets our bpf bytecode in kernel with our session handle */
    if (pcap_setfilter(handle, &bf)) {
        fprintf(stderr, "Couldn't set the filter %s\n", pcap_geterr(handle));
        return (2);
    }

    // Grabbing packet

    /* handle = session id, -1 = number of packets
    to sniff before stopping (-1 means infinite) */
    pcap_loop(handle, -1, packet_processing, (u_char *)&counter);

    // Closing session

    pcap_close(handle);

    return (0);
}