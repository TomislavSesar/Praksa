//sniffer_server.c

#include <pcap.h>
#include <stdio.h>

void obrada_paketa(u_char *args,
                   const struct pcap_pkthdr *header,
                   const u_char *packet) 
{
    //Counting packets
    int *counter = (int *)args;
    (*counter)++;

    printf("INFORMACIJE O PAKETU BROJ: %d", *counter);
    printf("Vrijeme:          %ld.%06ld\n", header->ts.tv_sec, header->ts.tv_usec);
    printf("Zaprimljeno bajtova: %d\n", header->caplen);
    printf("Stvarna velicina: %d\n", header->len);
    
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