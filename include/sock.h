#ifndef __SOCK_H__
#define __SOCK_H__

#include "oceanus.h"
#include "hash.h"
#include "ring.h"
#include <rte_ether.h>

#define SOCK_MAX_COUNT 65536
#define FIVE_TUPLE_SIZE (offsetof(five_tuple_t, protocol) + 1)

#define FIVE_TUPLE         \
    uint32_t sip, dip;     \
    uint16_t sport, dport; \
    uint8_t protocol;

typedef struct {
    FIVE_TUPLE
} five_tuple_t;

typedef struct sock {
    /* for tcp and udp */
    FIVE_TUPLE
    int fd;
    uint8_t mac[RTE_ETHER_ADDR_LEN];
    struct rte_ring *sendbuf, *recvbuf;
    pthread_mutex_t mutex;
    pthread_cond_t cond;

    /* only for tcp */
    uint32_t send_next, recv_next;
    //tcp_status_t status;
} sock_t;

typedef struct {
    struct rte_hash *five_tuples_hash;
    struct rte_hash *fds_hash;
} sock_table_t;


sock_table_t *get_sock_table_instance(void);

static inline sock_t *get_sock_from_fd(int fd)
{
    sock_table_t *sock_table = get_sock_table_instance();
    sock_t *sock = NULL;
    hash_lookup(sock_table->fds_hash, &fd, (void **)&sock);

    return sock;
}

static inline sock_t *get_sock_from_five_tuple(
        uint32_t sip, uint32_t sport, uint32_t dip, uint32_t dport, uint8_t protocol)
{
    sock_table_t *sock_table = get_sock_table_instance();
    five_tuple_t five_tuple = {
        .sip = sip,
        .sport = sport,
        .dip = dip,
        .dport = dport,
        .protocol = protocol,
    };

    sock_t *sock = NULL;
    hash_lookup(sock_table->five_tuples_hash, &five_tuple, (void **)&sock);

    return sock;
}

static inline void add_sock_to_fds_hash(sock_t *sock)
{
    sock_table_t *sock_table = get_sock_table_instance();
    if (get_sock_from_fd(sock->fd))
        return;

    hash_add(sock_table->fds_hash, &sock->fd, sock);
}

static inline void add_sock_to_five_tuples_hash(sock_t *sock)
{
    sock_table_t *sock_table = get_sock_table_instance();
    if (get_sock_from_five_tuple(sock->sip, sock->sport, sock->dip, sock->dport, sock->protocol))
        return;

    five_tuple_t five_tuple = {
        .sip = sock->sip,
        .sport = sock->sport,
        .dip = sock->dip,
        .dport = sock->dport,
        .protocol = sock->protocol,
    };

    hash_add(sock_table->five_tuples_hash, &five_tuple, sock);
}

static inline void remove_sock_from_sock_table(sock_t *sock)
{
    sock_table_t *sock_table = get_sock_table_instance();
    hash_del(sock_table->fds_hash, &sock->fd);

    five_tuple_t five_tuple = {
        .sip = sock->sip,
        .sport = sock->sport,
        .dip = sock->dip,
        .dport = sock->dport,
        .protocol = sock->protocol,
    };

    hash_del(sock_table->five_tuples_hash, &five_tuple);
}

static inline int32_t five_tuples_hash_iterate(const five_tuple_t **key, sock_t **sock, uint32_t *next)
{
    sock_table_t *sock_table = get_sock_table_instance();

    return hash_iterate(sock_table->five_tuples_hash, (const void **)key, (void **)sock, next);
}

#endif
