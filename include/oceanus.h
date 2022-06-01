#ifndef __OCEANUS_H__
#define __OCEANUS_H__

#include "epoll.h"
#include <arpa/inet.h>

void start_oceanus(int argc, char *argv[]);
int wait_oceanus(void);

/* posix API */
int o_socket(int domain, int type, int protocol);
int o_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int o_listen(int sockfd, int backlog);
int o_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
ssize_t o_recv(int sockfd, void *buf, size_t len, int flags);
ssize_t o_send(int sockfd, const void *buf, size_t len, int flags);
ssize_t o_recvfrom(int sockfd, void *buf, size_t len, int flags,
                        struct sockaddr *src_addr, socklen_t *addrlen);
ssize_t o_sendto(int sockfd, const void *buf, size_t len, int flags,
                      const struct sockaddr *dst_addr, socklen_t addrlen);
int o_close(int fd);

in_addr_t get_local_ip(void);

#endif
