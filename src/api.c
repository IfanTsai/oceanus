#include "fd.h"
#include "api.h"
#include "sock.h"
#include "config.h"
#include "udp.h"
#include "tcp.h"
#include <rte_tcp.h>
#include <rte_malloc.h>

#define RING_SIZE 1024

static uint8_t *g_this_mac;
static __fd_set_t *g_fd_set;

#define get_unused_fd() __get_unused_fd(g_fd_set)
#define put_unused_fd(fd) __put_unused_fd(g_fd_set, fd)

void init_api(config_t *cfg)
{
    g_this_mac = cfg->mac;
    g_fd_set = get_fd_set_instance();
}

int o_socket(int domain, int type, __attribute__((unused)) int protocol)
{
    if (domain != AF_INET) {
        errno = EAFNOSUPPORT;
        return -1;
    }

    int fd = get_unused_fd();
    if (fd < 0) {
        errno = EINVAL;
        return -1;
    }

    sock_t *sock = rte_zmalloc(NULL, sizeof(sock_t), 0);
    if (!sock) {
        errno = ENOMEM;
        return -1;
    }

    if (type == SOCK_STREAM) {
        sock->protocol = IPPROTO_TCP;
    } else if (type == SOCK_DGRAM) {
        sock->protocol = IPPROTO_UDP;
        char ring_name[32] = { 0 };
        snprintf(ring_name, sizeof(ring_name), "sock_recv_buff_%d", fd);
        sock->recvbuf = rte_ring_create(ring_name, RING_SIZE, rte_socket_id(),
                    RING_F_SP_ENQ | RING_F_SC_DEQ);
        if (!sock->recvbuf) {
            errno = ENOMEM;
            goto err_create_recv_buf;
        }

        snprintf(ring_name, sizeof(ring_name), "sock_send_buff_%d", fd);
        sock->sendbuf = rte_ring_create(ring_name, RING_SIZE, rte_socket_id(),
                    RING_F_SP_ENQ | RING_F_SC_DEQ);
        if (!sock->sendbuf) {
            errno = ENOMEM;
            goto err_create_send_buf;
        }
    }

    sock->fd = fd;

    pthread_mutex_init(&sock->mutex, NULL);
    pthread_cond_init(&sock->cond, NULL);

    add_sock_to_fds_hash(sock);

    return fd;

err_create_send_buf:
    rte_ring_free(sock->recvbuf);
err_create_recv_buf:
    rte_free(sock);

    return -1;
}

int o_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    if (addrlen != sizeof(struct sockaddr_in)) {
        errno = EINVAL;
        return -1;
    }

    sock_t *sock = get_sock_from_fd(sockfd);
    if (!sock) {
        errno = ENOTSOCK;
        return -1;
    }

    const struct sockaddr_in *addr_in = (const struct sockaddr_in *)addr;
    rte_memcpy(sock->mac, g_this_mac, RTE_ETHER_ADDR_LEN);
    if (sock->protocol == IPPROTO_TCP) {
        sock->dip = addr_in->sin_addr.s_addr;
        sock->dport = addr_in->sin_port;
        sock->status = TCP_STATUS_CLOSED;
    } else {
        sock->sip = addr_in->sin_addr.s_addr;
        sock->sport = addr_in->sin_port;
    }

    add_sock_to_five_tuples_hash(sock);

    return 0;
}

int o_listen(int sockfd, __attribute__((unused)) int backlog)
{
    sock_t *sock = get_sock_from_fd(sockfd);
    if (!sock) {
        errno = ENOTSOCK;
        return -1;
    }

    if (sock->protocol != IPPROTO_TCP) {
        errno = EPROTOTYPE;
        return -1;
    }

    sock->status = TCP_STATUS_LISTEN;

    add_sock_to_dports_listen_hash(sock);

    return 0;
}

int o_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    sock_t *listen_sock = get_sock_from_fd(sockfd);
    if (!listen_sock) {
        errno = ENOTSOCK;
        return -1;
    }


    if (listen_sock->protocol != IPPROTO_TCP) {
        errno = EPROTOTYPE;
        return -1;
    }

    sock_t *accept_sock = NULL;

    pthread_mutex_lock(&listen_sock->mutex);
    while ( !(accept_sock = get_accept_sock(listen_sock->dport)))
        pthread_cond_wait(&listen_sock->cond, &listen_sock->mutex);
    pthread_mutex_unlock(&listen_sock->mutex);

    if (accept_sock->fd != FD_UNINITIALIZE) {
        errno = EINVAL;
        return -1;
    }

    accept_sock->fd = get_unused_fd();
    struct sockaddr_in *src_addr_in = (struct sockaddr_in *)addr;
    src_addr_in->sin_addr.s_addr = accept_sock->sip;
    src_addr_in->sin_port = accept_sock->sport;
    *addrlen = sizeof(struct sockaddr_in);

    add_sock_to_fds_hash(accept_sock);

    return accept_sock->fd;
}

ssize_t o_recv(int sockfd, void *buf, size_t len, __attribute__((unused)) int flags)
{
    sock_t *sock = get_sock_from_fd(sockfd);
    if (!sock) {
        errno = ENOTSOCK;
        return -1;
    }

    if (sock->protocol != IPPROTO_TCP) {
        errno = EPROTOTYPE;
        return -1;
    }

    tcp_fragment_t *fragment;
    pthread_mutex_lock(&sock->mutex);
    while (rte_ring_mc_dequeue(sock->recvbuf, (void **)&fragment) < 0)
        pthread_cond_wait(&sock->cond, &sock->mutex);
    pthread_mutex_unlock(&sock->mutex);

    if (fragment->length == 0) {
        rte_free(fragment);

        return 0;
    }

    if (len < fragment->length) {
        // put data to user
        rte_memcpy(buf, fragment->data, len);

        // move data forward
        rte_memcpy(fragment->data, fragment->data + len, fragment->length - len);
        fragment->length -= len;

        // put back to the send ring buffer
        rte_ring_mp_enqueue(sock->recvbuf, fragment);

        return len;
    }

    uint16_t data_len = fragment->length;
    rte_memcpy(buf, fragment->data, data_len);
    rte_free(fragment->data);
    rte_free(fragment);

    return data_len;
}

ssize_t o_send(int sockfd, const void *buf, size_t len, __attribute__((unused)) int flags)
{
    sock_t *sock = get_sock_from_fd(sockfd);
    if (!sock) {
        errno = ENOTSOCK;
        return -1;
    }

    if (sock->protocol != IPPROTO_TCP) {
        errno = EPROTOTYPE;
        return -1;
    }

    if ( !send_fragment_with_data(sock, buf, len) ) {
        errno = ENOMEM;
        return -1;
    }

    return len;
}

ssize_t o_recvfrom(int sockfd, void *buf, size_t len, __attribute__((unused)) int flags,
                        struct sockaddr *src_addr, socklen_t *addrlen)
{
    sock_t *sock = get_sock_from_fd(sockfd);
    if (!sock) {
        errno = ENOTSOCK;
        return -1;
    }


    udp_payload_t *payload;
    pthread_mutex_lock(&sock->mutex);
    while (rte_ring_mc_dequeue(sock->recvbuf, (void **)&payload) < 0)
        pthread_cond_wait(&sock->cond, &sock->mutex);
    pthread_mutex_unlock(&sock->mutex);

    struct sockaddr_in *src_addr_in = (struct sockaddr_in *)src_addr;
    src_addr_in->sin_addr.s_addr = payload->sip;
    src_addr_in->sin_port = payload->sport;
    *addrlen = sizeof(struct sockaddr_in);

    if (len < payload->length) {
        // put data to user
        rte_memcpy(buf, payload->data, len);

        // move data forward
        rte_memcpy(payload->data, payload->data + len, payload->length - len);
        payload->length -= len;

        // put back to the send ring buffer
        rte_ring_mp_enqueue(sock->recvbuf, payload);

        return len;
    }

    uint16_t payload_len = payload->length;
    rte_memcpy(buf, payload->data, payload_len);
    rte_free(payload->data);
    rte_free(payload);

    return payload_len;
}

ssize_t o_sendto(int sockfd, const void *buf, size_t len, __attribute__((unused)) int flags,
                      const struct sockaddr *dst_addr, socklen_t addrlen)
{
    if (addrlen != sizeof(struct sockaddr_in)) {
        errno = EINVAL;
        return -1;
    }

    sock_t *sock = get_sock_from_fd(sockfd);
    if (!sock) {
        errno = ENOTSOCK;
        return -1;
    }

    udp_payload_t *payload = rte_malloc(NULL, sizeof(udp_payload_t), 0);
    if (!payload)
        return -1;

    const struct sockaddr_in *dst_addr_in = (const struct sockaddr_in *)dst_addr;
    payload->dip = dst_addr_in->sin_addr.s_addr;
    payload->dport = dst_addr_in->sin_port;
    payload->sip = sock->sip;
    payload->sport = sock->sport;
    payload->length = len;

    payload->data = rte_zmalloc(NULL, len, 0);
    if (!payload->data) {
        errno = ENOMEM;
        return -1;
    }

    rte_memcpy(payload->data, buf, len);

    rte_ring_mp_enqueue(sock->sendbuf, payload);

    return len;
}

int o_close(int fd)
{
    sock_t *sock = get_sock_from_fd(fd);
    if (!sock) {
        errno = ENOTSOCK;
        return -1;
    }

    if (sock->protocol == IPPROTO_TCP && sock->status != TCP_STATUS_LISTEN) {
        send_fin_fragment(sock);
        sock->status = TCP_STATUS_LAST_ACK;
    } else {
        remove_sock_from_sock_table(sock);
        rte_ring_free(sock->sendbuf);
        rte_ring_free(sock->recvbuf);
        rte_free(sock);
    }

    put_unused_fd(fd);

    return 0;
}
