//sniffer_server.c
#include <pcap.h>
#include <stdio.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h> 

#define ETH_LENGHT 14

void obrada_paketa(u_char *args,
                   const struct pcap_pkthdr *header,
                   const u_char *packet) 
{
    char *protocol="#";
    char *src_ip;
    char *dst_ip;
    __be16 src_port;
    __be16 dst_port;
    int *counter = (int *)args;

    //Counting packets

    (*counter)++;

    //ETH header

    //Packet's first header is eth header that conatins source and destination mac address
    // ether_header strcuture contains: uint8_t ether_dhost(dst_mac), uint8_t ether_shost(src_mac), uint16_t ether type
    const struct ether_header *eth = (const struct ether_header *)packet;
    
    //ehther_shost, ether_dhost need to be cast because function ether_nota only 
    //accepts ether_addr structure, ether_nota turns raw bytes into readable mac address
    char *src_mac = ether_ntoa((struct ether_addr *)eth->ether_shost);
    char *dst_mac = ether_ntoa((struct ether_addr *)eth->ether_dhost);

    //IP header
    /*iphdr contains 
    ihl = Internet Header lenght
    version = IP version(always 4)
    tos = Type of service, how packet is going to be handled
    tot_len = total lenght of packet
    id = when payload is fragmeneted, what is position of our packet 
    frag_off = fragment offeset 
    ttl = time to live
    protocol
    check = header check sum  
    saddr = source ip
    daddr = destination ip
    */
    const struct iphdr *ip =(const struct iphdr*)(packet+ETH_LENGHT);

    //Checking which protocol is used
    switch(ip->protocol){
        case IPPROTO_UDP: protocol = "UDP"; break;
        case IPPROTO_TCP: protocol = "TCP"; break;
        default: break;
    }

    //Help struture that is storing ip address and with function inet_ntoa,
    //turining bytes in IP address form 
    struct in_addr addr;

    addr.s_addr = ip->saddr;
    src_ip = inet_ntoa(addr);

    addr.s_addr = ip->daddr;
    dst_ip = inet_ntoa(addr);

    //If we want to know what port our traffic is going to first we need to 
    //know which protocol is proccessing our traffic
    
    //Lenght of ETH header is fixed = 14, bud leght of IP can vary from 20 to 60 bytes,
    //for that reason we need to use ip->ihl which tell us ip header lenght and multiply 
    //it with 4 to get true size in bytes

    //TCP header

    if(ip->protocol == IPPROTO_TCP){

        const struct tcphdr *tcph = (const struct tcphdr*) (packet+ETH_LENGHT + ip->ihl*4);
        src_port = ntohs(tcph->source);
        dst_port = ntohs(tcph->dest);

    }

    //UDP header

    else if(ip->protocol == IPPROTO_UDP){
        const struct udphdr *udph = (const struct udphdr*) (packet+ETH_LENGHT + ip->ihl*4);
        src_port = ntohs(udph->source);
        dst_port = ntohs(udph->dest);
    }



    if (protocol == "#"){
        printf("%d: %s -> %s; 0x%02x; %s: %d -> %s: %d\n", 
        *counter, src_mac, dst_mac, ip->protocol, src_ip, src_port, dst_ip, dst_port);
    }else{
        printf("%d: %s -> %s; %s; %s: %d -> %s: %d\n", 
        *counter, src_mac, dst_mac, protocol, src_ip, src_port, dst_ip, dst_port);
    }
    
}

int main(int argc, char *argv[]){
    
    char *device = argv[1];   //inerface that we are going to sniff (eth0)

    pcap_t *handle;  //sessions handle (smth like id)

    char errbuf[PCAP_ERRBUF_SIZE]; //buffer(string) that contains our error message if there is any

    //struct bpf_program f; //contains our compiled filter 

    bpf_u_int32 mask; //netmask of device that is sniffing

    bpf_u_int32 net; //ip adress of out sniffing device

    struct pcap_pkthdr header; //metadata about our packet (time, number of capture bytes, real packet size)

    const u_char *packet; //packet, it is u_char type because our packet is just stream of bytes

    int counter = 0; //Couner for counting our packets

    //Initilazing our device that is going to be sniffing


    if (pcap_lookupnet(device, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Nije valjan interface %s: %s\n", device, errbuf);
        net = 0;
		mask = 0;
        return 2;
    }

    //Opening session
    
    //device = interface, BUFSIZE = max bytes per packet, 
    //1 = promiscuosu mode, 1000 = timeout how long does it wait for packet, errbuf = string taht stores error 

    handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf); //setting session id 

	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", device, errbuf);
		return(2);
	}

    //Grabbing out packet

    pcap_loop(handle, -1, obrada_paketa, (u_char *)&counter); //handle = id session, -1 = number of packet to sniff before stopping(-1 means infinte)


    //Closing session

    pcap_close(handle);


	return(0);
}