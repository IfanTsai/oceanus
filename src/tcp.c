#include "tcp.h"
#include "arp_table.h"
#include "arp.h"
#include "sock.h"
#include "mbuf.h"
#include "hash.h"
#include "util.h"
#include "netdev.h"
#include "epoll.h"
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>

#define RING_SIZE 1024

static void notify_epoll_all(int fd, uint32_t event)
{
    const int *key = NULL;
    uint32_t next = 0;
    eventpoll_t *ep = NULL;

    while (fds_hash_eventpoll_iterate(&key, &ep, &next) >= 0)
        epoll_event_cb(ep, fd, event);
}

static inline void
create_tcp_pkt(struct rte_mbuf *mbuf,
        uint8_t *smac, uint8_t *dmac, uint32_t sip, uint32_t dip, tcp_fragment_t *fragment)
{
    struct rte_ether_hdr *ethdr = mbuf_ethdr(mbuf);
    struct rte_ipv4_hdr *iphdr = mbuf_iphdr(mbuf);
    struct rte_tcp_hdr *tcphdr = mbuf_tcphdr(mbuf);

    rte_memcpy(ethdr->s_addr.addr_bytes, smac, RTE_ETHER_ADDR_LEN);
    rte_memcpy(ethdr->d_addr.addr_bytes, dmac, RTE_ETHER_ADDR_LEN);
    ethdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

    iphdr->version_ihl = 0x45;
    iphdr->type_of_service = 0;
    iphdr->total_length = rte_cpu_to_be_16(mbuf->data_len - sizeof(*ethdr));
    iphdr->packet_id = 0;
    iphdr->fragment_offset = 0;
    iphdr->time_to_live = 64;
    iphdr->next_proto_id = IPPROTO_TCP;
    iphdr->src_addr = sip;
    iphdr->dst_addr = dip;
    iphdr->hdr_checksum = 0;
    iphdr->hdr_checksum = rte_ipv4_cksum(iphdr);

    tcphdr->src_port = fragment->sport;
    tcphdr->dst_port = fragment->dport;
    tcphdr->sent_seq = rte_cpu_to_be_32(fragment->seq);
    tcphdr->recv_ack = rte_cpu_to_be_32(fragment->ack);
    tcphdr->data_off = fragment->data_off;
    tcphdr->rx_win = fragment->win;
    tcphdr->tcp_urp = fragment->urp;
    tcphdr->tcp_flags = fragment->flags;

    if (fragment->length > 0) {
        uint8_t *payload = (uint8_t *) (tcphdr + 1) + fragment->option_len * sizeof(uint32_t);
        rte_memcpy(payload, fragment->data, fragment->length);
    }

    tcphdr->cksum = 0;
    tcphdr->cksum = rte_ipv4_udptcp_cksum(iphdr, tcphdr);
}

static inline
tcp_fragment_t *create_empty_data_fragment(uint16_t sport, uint16_t dport, uint32_t seq, uint32_t ack)
{
    tcp_fragment_t *fragment = rte_malloc(NULL, sizeof(tcp_fragment_t), 0);
    if (!fragment)
        return NULL;

    fragment->sport = sport;
    fragment->dport = dport;
    fragment->seq = seq;
    fragment->ack = ack;
    fragment->win = TCP_INITIAL_WINDOW;
    fragment->data_off = 0x50;
    fragment->data = NULL;
    fragment->length = 0;

    return fragment;
}

static inline tcp_fragment_t *create_ack_fragment(sock_t *sock)
{
    tcp_fragment_t *fragment =
	create_empty_data_fragment(sock->dport, sock->sport, sock->send_next, sock->recv_next);
    if (!fragment)
        return NULL;

    fragment->flags = RTE_TCP_ACK_FLAG;

    return fragment;
}

static inline tcp_fragment_t *send_ack_fragment(sock_t *sock)
{
    tcp_fragment_t *fragment = create_ack_fragment(sock);
    if (!fragment)
        return NULL;

    rte_ring_mp_enqueue(sock->sendbuf, fragment);

    return fragment;
}

static inline tcp_fragment_t *send_syn_fragment(sock_t *sock)
{
    tcp_fragment_t *fragment = create_ack_fragment(sock);
    if (!fragment)
        return NULL;

    fragment->flags |= RTE_TCP_SYN_FLAG;

    rte_ring_mp_enqueue(sock->sendbuf, fragment);

    return fragment;
}

static inline void send_rst_fragment(config_t *cfg, struct rte_mbuf *mbuf)
{
    struct rte_ether_hdr *ethdr = mbuf_ethdr(mbuf);
    struct rte_ipv4_hdr *iphdr = mbuf_iphdr(mbuf);
    struct rte_tcp_hdr *tcphdr = mbuf_tcphdr(mbuf);

    swap_mac(ethdr);
    swap_ip(iphdr);
    swap_port(tcphdr);

    tcphdr->recv_ack = rte_cpu_to_be_32(rte_be_to_cpu_32(tcphdr->sent_seq) + 1);
    tcphdr->sent_seq = 0;
    tcphdr->tcp_flags = RTE_TCP_ACK_FLAG | RTE_TCP_RST_FLAG;
    tcphdr->data_off = 0x50;
    tcphdr->cksum = 0;
    tcphdr->cksum = rte_ipv4_udptcp_cksum(iphdr, tcphdr);

    netdev_tx_commit(cfg, &mbuf);
}

tcp_fragment_t *send_fin_fragment(sock_t *sock)
{
    tcp_fragment_t *fragment = create_ack_fragment(sock);
    if (!fragment)
        return NULL;

    fragment->flags |= RTE_TCP_FIN_FLAG;

    rte_ring_mp_enqueue(sock->sendbuf, fragment);

    return fragment;
}

tcp_fragment_t *send_fragment_with_data(sock_t *sock, const void *buf, size_t len)
{
    tcp_fragment_t *fragment = create_ack_fragment(sock);
    fragment->flags |= RTE_TCP_PSH_FLAG;
    fragment->data = rte_malloc(NULL, len, 0);
    if (!fragment->data) {
        rte_free(fragment);

        return NULL;
    }

    rte_memcpy(fragment->data, buf, len);
    fragment->length = len;

    rte_ring_mp_enqueue(sock->sendbuf, fragment);

    return fragment;
}

static inline int put_fragment_to_recv_buf(sock_t *sock, struct rte_tcp_hdr *tcphdr, uint8_t *data, uint32_t len)
{
    tcp_fragment_t *fragment =
        create_empty_data_fragment(rte_be_to_cpu_16(tcphdr->dst_port), rte_be_to_cpu_16(tcphdr->src_port), 0, 0);

    if (!fragment)
        return -1;

    if (data && len > 0) {
        fragment->data = rte_malloc(NULL, len, 0);
        if (!fragment->data) {
            rte_free(fragment);
            return -1;
        }

        rte_memcpy(fragment->data, data, len);
    }

    fragment->length = len;

    rte_ring_mp_enqueue(sock->recvbuf, fragment);
    pthread_mutex_lock(&sock->mutex);
    pthread_cond_signal(&sock->cond);
    pthread_mutex_unlock(&sock->mutex);

    return 0;
}

static inline uint32_t calc_four_tuple_hash(uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport)
{
    five_tuple_t five_tuple = {
        .sip = sip,
        .dip = dip,
        .sport = sport,
        .dport = dport,
        .protocol = IPPROTO_TCP,
    };

    return jhash(&five_tuple, sizeof(five_tuple));
}

static sock_t *create_tcp_sock(uint8_t *mac, uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport)
{
    sock_t *sock = rte_zmalloc(NULL, sizeof(sock_t), 0);
    if (!sock)
        return NULL;

    sock->sip = sip;
    sock->dip = dip;
    sock->sport = sport;
    sock->dport = dport;
    sock->status = TCP_STATUS_LISTEN;

    char ring_name[32] = { 0 };
    uint32_t hash = calc_four_tuple_hash(sip, dip, sport, dport);
    snprintf(ring_name, sizeof(ring_name), "sendbuf_%x", hash);
    sock->sendbuf = rte_ring_create(ring_name, RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (!sock->sendbuf)
        EEXIT("failed to alloc send buf");

    snprintf(ring_name, sizeof(ring_name), "recvbuf_%x", hash);
    sock->recvbuf = rte_ring_create(ring_name, RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (!sock->recvbuf)
        EEXIT("failed to alloc recv buf");

    sock->protocol = IPPROTO_TCP;
    sock->fd = FD_UNINITIALIZE;

    uint32_t next_seed = time(NULL);
    sock->send_next = rand_r(&next_seed) % TCP_MAX_SEQ;

    rte_memcpy(sock->mac, mac, RTE_ETHER_ADDR_LEN);

    add_sock_to_five_tuples_hash(sock);

    return sock;
}

static int process_tcp_last_ack(sock_t *sock, struct rte_tcp_hdr *tcphdr)
{
    if (sock->status != TCP_STATUS_LAST_ACK)
        return -1;

    if ( !(tcphdr->tcp_flags & RTE_TCP_ACK_FLAG) )
        return -1;

    sock->status = TCP_STATUS_CLOSED;

    remove_sock_from_sock_table(sock);
    rte_free(sock->sendbuf);
    rte_free(sock->recvbuf);
    rte_free(sock);

    return 0;
}

static int process_tcp_close_wait(sock_t *sock, __attribute__((unused)) struct rte_tcp_hdr *tcphdr)
{
    if (sock->status != TCP_STATUS_CLOSE_WAIT)
        return -1;

    return 0;
}

static int process_tcp_established(sock_t *sock, struct rte_tcp_hdr *tcphdr, uint16_t tcplen)
{
    if (tcphdr->tcp_flags & RTE_TCP_SYN_FLAG) {

    }

    if (tcphdr->tcp_flags & RTE_TCP_PSH_FLAG) {
        /* put payload fragment to user receive buffer, will get the payload by calling recv */
        tcp_fragment_t *recv_fragment = rte_zmalloc(NULL, sizeof(tcp_fragment_t), 0);
        if (!recv_fragment)
            return -1;

        uint8_t hdrlen = tcphdr->data_off >> 4;
        int payload_len = tcplen - hdrlen * 4;
        uint8_t *payload = (uint8_t *)tcphdr + hdrlen * 4;
        if (put_fragment_to_recv_buf(sock, tcphdr, payload, payload_len) < 0)
            return -1;

        /* return ack fragment to send buffer, will return ack to peer */
        sock->send_next = rte_be_to_cpu_32(tcphdr->recv_ack);
        sock->recv_next += payload_len;

        if (send_ack_fragment(sock) < 0)
            return -1;

        notify_epoll_all(sock->fd, EPOLLIN);
    }

    if (tcphdr->tcp_flags & RTE_TCP_ACK_FLAG) {
    }

    if (tcphdr->tcp_flags & RTE_TCP_FIN_FLAG) {
        sock->status = TCP_STATUS_CLOSE_WAIT;

        /* put empty data fragment to receive buffer, will return 0 by calling recv */
        if (put_fragment_to_recv_buf(sock, tcphdr, NULL, 0) < 0)
            return -1;

        /* return ack fragment to send buffer, will return ack to peer */
        sock->send_next = rte_be_to_cpu_32(tcphdr->recv_ack);
        sock->recv_next++;

        if (send_ack_fragment(sock) < 0)
            return -1;

        notify_epoll_all(sock->fd, EPOLLIN);
    }

    return 0;
}

static int process_tcp_syn_rcvd(sock_t *sock, struct rte_tcp_hdr *tcphdr)
{
    if ( !(tcphdr->tcp_flags & RTE_TCP_ACK_FLAG && sock->status == TCP_STATUS_SYN_RCVD) )
        return -1;

    if (rte_be_to_cpu_32(tcphdr->recv_ack) != sock->send_next + 1)
        return -1;

    sock->status = TCP_STATUS_ESTABLISHED;

    sock_t *listen_sock = get_listen_sock(sock->dport);
    if (!listen_sock)
        EEXIT("failed to get listen socket in TCP_STATUS_SYN_RCVD");

    add_sock_to_dports_accept_hash(sock);

    pthread_mutex_lock(&listen_sock->mutex);
    pthread_cond_signal(&listen_sock->cond);
    pthread_mutex_unlock(&listen_sock->mutex);

    notify_epoll_all(listen_sock->fd, EPOLLIN);

    return 0;
}

static int process_tcp_listen(config_t *cfg, struct rte_tcp_hdr *tcphdr, struct rte_ipv4_hdr *iphdr)
{
    if ( !(tcphdr->tcp_flags & RTE_TCP_SYN_FLAG) )
        return -1;

    sock_t *sock = create_tcp_sock(cfg->mac,
            iphdr->src_addr, iphdr->dst_addr, tcphdr->src_port, tcphdr->dst_port);
    if (!sock)
        return -1;

    sock->recv_next = rte_be_to_cpu_32(tcphdr->sent_seq) + 1;
    tcp_fragment_t *fragment = send_syn_fragment(sock);
    if (!fragment)
        goto err_malloc_fragment;

    sock->status = TCP_STATUS_SYN_RCVD;

    return 0;

err_malloc_fragment:
    remove_sock_from_sock_table(sock);
    rte_free(sock);

    return -1;
}

int process_tcp_pkt(config_t *cfg, struct rte_mbuf *mbuf)
{
    struct rte_ipv4_hdr *iphdr = mbuf_iphdr(mbuf);
    struct rte_tcp_hdr *tcphdr = mbuf_tcphdr(mbuf);

    uint16_t cksum = tcphdr->cksum;
    tcphdr->cksum = 0;
    if (cksum != rte_ipv4_udptcp_cksum(iphdr, tcphdr))
        return -1;

    sock_t *sock = get_sock_from_five_tuple(
            iphdr->src_addr, tcphdr->src_port, iphdr->dst_addr, tcphdr->dst_port, IPPROTO_TCP);

    // if the tcp status is not ESTABLISHED, maybe is LISTENING
    if (!sock) {
        if ( !(sock = get_listen_sock(tcphdr->dst_port)) ) {
            send_rst_fragment(cfg, mbuf);
            return 0;
        }
    }


    switch (sock->status) {
    case TCP_STATUS_CLOSED:
        break;

    case TCP_STATUS_LISTEN:
        if (process_tcp_listen(cfg, tcphdr, iphdr) < 0)
            return -1;
        break;

    case TCP_STATUS_SYN_RCVD:
        if (process_tcp_syn_rcvd(sock, tcphdr) < 0)
            return -1;
        break;

    case TCP_STATUS_SYN_SENT:
        break;

    case TCP_STATUS_ESTABLISHED: {
        uint16_t tcp_len = rte_be_to_cpu_16(iphdr->total_length) - sizeof(struct rte_ipv4_hdr);
        if (process_tcp_established(sock, tcphdr, tcp_len) < 0)
            return -1;
        break;
    }
    case TCP_STATUS_FIN_WAIT1:
        break;

    case TCP_STATUS_FIN_WAIT2:
        break;

    case TCP_STATUS_CLOSING:
        break;

    case TCP_STATUS_TIME_WAIT:
        break;

    case TCP_STATUS_CLOSE_WAIT:
        if (process_tcp_close_wait(sock, tcphdr) < 0)
            return -1;
        break;

    case TCP_STATUS_LAST_ACK:
        if (process_tcp_last_ack(sock, tcphdr) < 0)
            return -1;
        break;
    }

    rte_pktmbuf_free(mbuf);

    return 0;
}

void send_tcp_pkts(config_t *cfg)
{
    const five_tuple_t *key = NULL;
    uint32_t next = 0;
    sock_t *sock = NULL;
    while (five_tuples_sock_hash_iterate(&key, &sock, &next) >= 0) {
        if (sock->protocol != IPPROTO_TCP || sock->sendbuf == NULL)
            continue;

        tcp_fragment_t *fragments[BURST_SIZE];
        size_t nr_send;
        if ( (nr_send = rte_ring_mc_dequeue_burst(sock->sendbuf, (void **)fragments, BURST_SIZE, NULL)) < 0)
            continue;

        for (size_t i = 0; i < nr_send; i++) {
            tcp_fragment_t *fragment = fragments[i];
            uint8_t *dst_mac = get_dst_macaddr(sock->sip);  // client ip
            if (!dst_mac) {
                send_arp_pkt(cfg, g_arp_request_mac, sock->dip, RTE_ARP_OP_REQUEST);
                rte_ring_mp_enqueue(sock->sendbuf, fragment);
            } else {
                const unsigned total_length =
                sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_tcp_hdr) +
                fragment->option_len * sizeof(uint32_t) + fragment->length;

                struct rte_mbuf *mbuf = rte_pktmbuf_alloc(cfg->mpool);
                if (!mbuf)
                    EEXIT("failed to alloc mbuf");
                mbuf->pkt_len = mbuf->data_len = total_length;

                create_tcp_pkt(mbuf, sock->mac, dst_mac, sock->dip, sock->sip, fragment);
                en_out_ring_burst(cfg->ring, &mbuf, 1);
            }
        }

        for (size_t i = 0; i < nr_send; i++) {
            rte_free(fragments[i]->data);
            rte_free(fragments[i]);
        }
    }
}
