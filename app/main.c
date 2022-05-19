#include "oceanus.h"
#include <string.h>
#include <stdio.h>

#define IP "192.168.18.115"
#define UDP_PORT 8999
#define BUF_SIZE 1024

static void udp_server(void)
{
    int sockfd = o_socket(AF_INET, SOCK_DGRAM, 0);

    struct sockaddr_in servaddr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = inet_addr(IP),
        .sin_port = htons(UDP_PORT),
    };

    o_bind(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr));

    char buf[BUF_SIZE];
    struct sockaddr_in cliaddr = { 0 };
    socklen_t addrlen = sizeof(cliaddr);

    for (;;) {
        memset(buf, 0, sizeof(buf));

        ssize_t recvd = o_recvfrom(sockfd, buf, sizeof(buf), 0, (struct sockaddr *)&cliaddr, &addrlen);
        if (recvd < 0)
            continue;

        printf("udp recv from %s:%d, data: %s\n", inet_ntoa(cliaddr.sin_addr), ntohs(cliaddr.sin_port), buf);

        o_sendto(sockfd, buf, recvd, 0, (struct sockaddr *)&cliaddr, sizeof(cliaddr));
    }

    o_close(sockfd);
}

int main(int argc, char *argv[])
{
    start_oceanus(argc, argv);

    udp_server();

    return wait_oceanus();
}
