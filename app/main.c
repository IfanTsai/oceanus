#include "oceanus.h"
#include <string.h>
#include <stdio.h>

#define LOCAL_IP get_local_ip()
#define UDP_PORT 8999
#define TCP_PORT 8999
#define BUF_SIZE 1024

static void udp_server(void)
{
    int sockfd = o_socket(AF_INET, SOCK_DGRAM, 0);

    struct sockaddr_in servaddr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = LOCAL_IP,
        .sin_port = htons(UDP_PORT),
    };

    o_bind(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr));

    char buf[BUF_SIZE];
    struct sockaddr_in cliaddr = { 0 };
    socklen_t addrlen = sizeof(cliaddr);

    for (;;) {
        memset(buf, 0, sizeof(buf));

        ssize_t recvd = o_recvfrom(sockfd, buf, sizeof(buf), 0, (struct sockaddr *)&cliaddr, &addrlen);
        if (recvd < 0) {
            printf("recvfrom error: %s\n", strerror(errno));
            continue;
        }

        printf("udp recv from %s:%d, data: %s\n", inet_ntoa(cliaddr.sin_addr), ntohs(cliaddr.sin_port), buf);

        o_sendto(sockfd, buf, recvd, 0, (struct sockaddr *)&cliaddr, sizeof(cliaddr));
    }

    o_close(sockfd);
}

static void tcp_server(void)
{
    int listenfd = o_socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in servaddr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = LOCAL_IP,
        .sin_port = htons(TCP_PORT),
    };

    struct sockaddr_in cliaddr = { 0 };
    socklen_t addrlen = sizeof(cliaddr);

    o_bind(listenfd, (struct sockaddr *)&servaddr, sizeof(servaddr));

    o_listen(listenfd, 128);

    int epfd = o_epoll_create(1);

    struct epoll_event ev = {
        .events = EPOLLIN,
        .data.fd = listenfd,
    };
    o_epoll_ctl(epfd, EPOLL_CTL_ADD, listenfd, &ev);

    struct epoll_event events[128];

    for (;;) {
        int num_events = o_epoll_wait(epfd, events, sizeof(events), 100);
        if (num_events < 0) {
            printf("epoll_wait error: %s\n", strerror(errno));
            continue;
        }

        for (int i = 0; i < num_events; i++) {
            if (listenfd == events[i].data.fd) {
                int connfd = o_accept(listenfd, (struct sockaddr *)&cliaddr, &addrlen);
                printf("accept client, connfd = %d\n", connfd);

                struct epoll_event ev = {
                    .events = EPOLLIN,
                    .data.fd = connfd,
                };

                o_epoll_ctl(epfd, EPOLL_CTL_ADD, connfd, &ev);
            } else {
                int connfd = events[i].data.fd;
                char buf[BUF_SIZE] = { 0 };

                ssize_t n = o_recv(connfd, buf, sizeof(buf), 0);
                if (n == 0) {
                    printf("close client, confd = %d\n", connfd);
                    o_epoll_ctl(epfd, EPOLL_CTL_DEL, connfd, NULL);
                    o_close(connfd);
                    continue;
                } else if (n < 0) {
                    printf("recv error: %s\n", strerror(errno));
                    continue;
                }

                printf("tcp recv from %s:%d, data: %s\n", inet_ntoa(cliaddr.sin_addr), ntohs(cliaddr.sin_port), buf);

                o_send(connfd, buf, n, 0);

            }
        }
    }

    o_close(epfd);
    o_close(listenfd);
}

int main(int argc, char *argv[])
{
    start_oceanus(argc, argv);

    tcp_server();

    return wait_oceanus();
}
