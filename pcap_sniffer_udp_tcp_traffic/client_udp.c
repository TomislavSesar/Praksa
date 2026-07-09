// client.c

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#define PORT 9000
int main(void)
{

    int status, valread, client_fd;
    char *message = "Message sent";
    struct sockaddr_in serv_addr;
    char buffer[1024] = {0};

    // Initializing socket
    if ((client_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Socket: ");
        return -1;
    }

    /* Setting where our packets are going to be received (.sin_family
    AF_INET=IPv4, .s_addr=packets can come from any address, .sin_port=port that
    is going to process our packets)*/

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    /* As this is client side we need exact IP address where packets
    are going to be sent and we need to turn our IP address into
    binary format */

    if (inet_pton(AF_INET, "10.0.0.10", &serv_addr.sin_addr) <= 0) {
        fprintf(stderr, "Inavlid adress");
        return -1;
    }

    // Structure that is holding recipient information
    struct sockaddr_in from;
    socklen_t from_len = sizeof(from);

    // Sending packets

    while (1) {
        memset(buffer, 0, sizeof(buffer));
        ssize_t sent = sendto(client_fd, message, strlen(message), 0,
                              (struct sockaddr *)&serv_addr, sizeof(serv_addr));

        if (sent < 0) {
            int err = errno;
            perror("sendto: ");
            if (err == EINTR) {
                continue;
            }
            break;
        }

        printf("Message sent\n");

        valread = recvfrom(client_fd, buffer, 1024 - 1, 0,
                           (struct sockaddr *)&from, &from_len);

        if (valread < 0) {
            int err = errno;
            perror("recvfrom: ");
            break;
        }
        printf("Server response: %s\n", buffer);
    }

    if (close(client_fd) < 0) {
        perror("close: ");
    }

    return 0;
}