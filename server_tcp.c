#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#define PORT 9000
int main(void)
{
    int server_fd, new_socket;
    int op = 1;
    struct sockaddr_in address;
    struct sockaddr_in address_client;
    char buffer[1024] = {0};
    char *message = "Message from server";

    // Initializing socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("exit: ");
        exit(EXIT_FAILURE);
    }

    /* Setting up some socket options SO_REUSEADDR = we don't have to wait if
    tcp connection is timed out SO_REUSEPORT = multiple processes can listen on
    one port */
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &op,
                   sizeof(op))) {
        perror("setsockopt: ");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind: ");
        exit(EXIT_FAILURE);
    }

    // Listen function -> caps out how many clients can be in accept queue
    if (listen(server_fd, 3) < 0) {
        perror("listen: ");
        exit(EXIT_FAILURE);
    }

    while (1) {
        printf("Waiting for client\n");
        socklen_t addrlen_client = sizeof(address_client);
        if ((new_socket = accept(server_fd, (struct sockaddr *)&address_client,
                                 &addrlen_client)) < 0) {
            perror("accept: ");
            exit(EXIT_FAILURE);
        }

        while (1) {
            memset(buffer, 0, sizeof(buffer));
            int valread = read(new_socket, buffer, sizeof(buffer) - 1);
            // valread == 0 -> connection closed, <0 -> error
            if (valread < 0) {
                perror("read: ");
                break;
            } else if (valread == 0) {
                printf("Connection closed");
            }

            if (send(new_socket, message, strlen(message), 0) < 0) {
                perror("send: ");
                break;
            }

            printf("Message received: %s\n", buffer);
        }

        if (close(new_socket) < 0) {
            perror("close");
        }
    }

    if (close(server_fd) < 0) {
        perror("close:")
    }
    return 0;
}