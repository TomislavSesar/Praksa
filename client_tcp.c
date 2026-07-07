#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#define PORT 9000

int main(void)
{
    int client_fd, status, valread;
    char *poruka = "Poruka od klijeta";
    struct sockaddr_in serv_addr;
    char buffer[1024] = {0};

    if ((client_fd = socket(AF_INET, SOCK_STREAM, 0)) <
        0) { // Initilazing socket for TCP
        printf("\n Greska \n");
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    if (inet_pton(AF_INET, "10.0.0.10", &serv_addr.sin_addr) <= 0) {
        printf("\nInvalid address/ Address not supported \n");
        return -1;
    }

    if ((status = connect(client_fd, (struct sockaddr *)&serv_addr,
                          sizeof(serv_addr))) < 0) {
        printf("Connection failed\n");
        return -1;
    }

    while (1) {

        memset(buffer, 0, sizeof(buffer));

        send(client_fd, poruka, strlen(poruka), 0);

        printf("Poruka poslana\n");

        valread = read(client_fd, buffer, 1024 - 1);

        printf("%s\n", buffer);
    }

    close(client_fd);
}