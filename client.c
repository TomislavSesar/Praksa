//client.c

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#define PORT 9000
int main(void)
{


    int status, valread, client_fd;
    char* poruka = "Poruka od klijeta";
    struct sockaddr_in serv_addr;
    char buffer[1024] = { 0 };

    if ((client_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) { // Initilazing socket
        printf("\n Greska \n");
        return -1;
    }

    //Setting where out packet are going to recived (.sinfamiy AF_INET=IPv4, 
    //.s_addr=packets can come from any address, .sinport=port that is going to
    //proccess our packets)

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    //As this is client side we need exact IP address where packets 
    //are going to be sendt and we need to turn our IP adress in
    //binary format

    if (inet_pton(AF_INET, "10.0.0.21", &serv_addr.sin_addr)
        <= 0) {
        printf(
            "\nInvalid address/ Address not supported \n");
        return -1;
    }


    //Structure that is holding recipiet information
    struct sockaddr_in from;
    socklen_t from_len = sizeof(from);

    //Sending packets 

    while(1){
        memset(buffer, 0, sizeof(buffer));
        sendto(client_fd, poruka, strlen(poruka), 0,
            (struct sockaddr*)&serv_addr, sizeof(serv_addr));

        printf("Poruka poslana\n");

        valread = recvfrom(client_fd, buffer, 1024-1, 0,
                   (struct sockaddr*)&from, &from_len);
        printf("Odgovor servera: %s\n", buffer);

    }

    close(client_fd);


    return 0;

}