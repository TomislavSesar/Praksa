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
    char *message = "Message sent";
    struct sockaddr_in serv_addr;
    char buffer[1024] = {0};

    // Initilazing socket for TCP
    if ((client_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket: ");
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    if (inet_pton(AF_INET, "10.0.0.10", &serv_addr.sin_addr) <= 0) {
        fprintf(stderr, "Inavlid adress");
        return -1;
    }

    if ((status = connect(client_fd, (struct sockaddr *)&serv_addr,
                          sizeof(serv_addr))) < 0) {
        perror("connect: ");
        return -1;
    }

    while (1) {

        memset(buffer, 0, sizeof(buffer));

        if (send(client_fd, message, strlen(message), 0) < 0) {
            perror("send: ");
            break;
        }

        printf("Message sent\n");

        valread = read(client_fd, buffer, 1024 - 1);

        if (valread < 0) {
            perror("read: ");
            break;
        } else if (valread == 0) {
            printf("Connection closed");
            break;
        }

        printf("%s\n", buffer);
    }

    if (close(client_fd)) {
        perror("close: ");
    }

    return 0;
}