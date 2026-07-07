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
    char *message = "Prva poruka sa servera";

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) <
        0) { // Initilazing socket
        exit(EXIT_FAILURE);
    }

    // Setting up some socket options SO_REUSEADDR = we don't have to wait if
    // tcp conneciton is timedout SO_REUSEPORT = multiple proccess can listen on
    // one port
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &op,
                   sizeof(op))) {
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        exit(EXIT_FAILURE);
    }

    // Listen fuction -> caps out how many clients can be in acceppt queue
    if (listen(server_fd, 3) < 0) {
        exit(EXIT_FAILURE);
    }

    while (1) {
        printf("Cekanje klijenta\n");
        socklen_t addrlen_client = sizeof(address_client);
        if ((new_socket = accept(server_fd, (struct sockaddr *)&address_client,
                                 &addrlen_client)) < 0) {

            exit(EXIT_FAILURE);
        }

        while (1) {
            memset(buffer, 0, sizeof(buffer));
            int valread = read(new_socket, buffer, sizeof(buffer) - 1);
            if (valread <= 0) {
                printf("Klijent se odspojio");
                break; // valread == 0 -> konkecija zavtorena, <0 ->greska
            }

            send(new_socket, message, strlen(message), 0);

            printf("Primljena poruka: %s\n", buffer);
        }

        close(new_socket);
    }

    close(server_fd);
}