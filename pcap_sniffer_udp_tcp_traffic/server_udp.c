// server.c
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#define PORT 9000
int main(void)
{
    int server_fd;
    int op = 1;
    struct sockaddr_in address;
    char buffer[1024] = {0};
    char *message = "Message from server";

    // Initializing socket
    if ((server_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket: ");
        exit(EXIT_FAILURE);
    }

    // Setting socket options, it is not necessary for udp packet transport

    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &op,
                   sizeof(op))) {
        perror("setsocketopt: ");
        exit(EXIT_FAILURE);
    }

    /* Setting where our packets are going to be received (.sin_family
    AF_INET=IPv4, .s_addr=packets can come from any address, .sin_port=port that
    is going to process our packets) */

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    // Binding socket with sockaddr_in structure

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind: ");
        exit(EXIT_FAILURE);
    }

    // Structure that is holding information about our sender (client)

    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);

    // Waiting for packets, and sending response back to the sender

    while (1) {
        memset(buffer, 0, sizeof(buffer));
        int valread = recvfrom(server_fd, buffer, 1024 - 1, 0,
                               (struct sockaddr *)&client_addr, &client_len);

        if (valread < 0) {
            int err = errno;
            perror("recvfrom: ");
            break;
        }

        printf("Accepted: %s\n", buffer);

        ssize_t sent = sendto(server_fd, message, strlen(message), 0,
                              (struct sockaddr *)&client_addr, client_len);

        if (sent < 0) {
            int err = errno;
            perror("sendto: ");
            if (err == EINTR) {
                continue;
            }
            break;
        }
    }

    if (close(server_fd) < 0) {
        perror("close: ");
    }

    return 0;
}