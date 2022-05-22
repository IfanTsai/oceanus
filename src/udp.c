#include "udp.h"
#include "sock.h"
#include "mbuf.h"
#include "arp_table.h"
#include "arp.h"
#include "ring.h"

static inline void
create_udp_packet(struct rte_mbuf *mbuf, uint8_t *smac, uint8_t *dmac, udp_payload_t *payload)
{
    struct rte_ether_hdr *ethdr = mbuf_ethdr(mbuf);
    struct rte_ipv4_hdr *iphdr = mbuf_iphdr(mbuf);
    struct rte_udp_hdr *udphdr = mbuf_udphdr(mbuf);

    rte_memcpy(ethdr->s_addr.addr_bytes, smac, RTE_ETHER_ADDR_LEN);
    rte_memcpy(ethdr->d_addr.addr_bytes, dmac, RTE_ETHER_ADDR_LEN);
    ethdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

    iphdr->version_ihl = 0x45;
    iphdr->type_of_service = 0;
    iphdr->total_length = rte_cpu_to_be_16(mbuf->data_len - sizeof(*ethdr));
    iphdr->packet_id = 0;
    iphdr->fragment_offset = 0;
    iphdr->time_to_live = 64;
    iphdr->next_proto_id = IPPROTO_UDP;
    iphdr->src_addr = payload->sip;
    iphdr->dst_addr = payload->dip;
    iphdr->hdr_checksum = 0;
    iphdr->hdr_checksum = rte_ipv4_cksum(iphdr);

    udphdr->src_port = payload->sport;
    udphdr->dst_port = payload->dport;
    uint16_t udp_len = mbuf->data_len - sizeof(*ethdr) - sizeof(*iphdr);
    rte_memcpy((void *)(udphdr + 1), payload->data, udp_len - sizeof(*udphdr));
    udphdr->dgram_len = rte_cpu_to_be_16(udp_len);
    udphdr->dgram_cksum = 0;
    udphdr->dgram_cksum = rte_ipv4_udptcp_cksum(iphdr, udphdr);
}

int process_udp_pkt(__attribute__((unused)) config_t *cfg, struct rte_mbuf *mbuf)
{
    struct rte_ipv4_hdr *iphdr = mbuf_iphdr(mbuf);
    struct rte_udp_hdr *udphdr = mbuf_udphdr(mbuf);

    sock_t *sock = get_sock_from_five_tuple(iphdr->dst_addr, udphdr->dst_port, 0, 0, iphdr->next_proto_id);
    if (!sock)
        return -1;

    udp_payload_t *payload = rte_malloc(NULL, sizeof(udp_payload_t), 0);
    if (!payload)
        return -1;

    payload->dip = iphdr->dst_addr;
    payload->sip = iphdr->src_addr;
    payload->sport = udphdr->src_port;
    payload->dport = udphdr->dst_port;
    payload->length = rte_be_to_cpu_16(udphdr->dgram_len);
    payload->data = rte_malloc(NULL, payload->length - sizeof(struct rte_udp_hdr), 0);
    if (!payload->data) {
        rte_free(payload);

        return -1;
    }
    rte_memcpy(payload->data, udphdr + 1, payload->length);

    rte_ring_mp_enqueue(sock->recvbuf, payload);

    pthread_mutex_lock(&sock->mutex);
    pthread_cond_signal(&sock->cond);
    pthread_mutex_unlock(&sock->mutex);

    rte_pktmbuf_free(mbuf);

    return 0;
}

void send_udp_pkts(config_t *cfg)
{
    const five_tuple_t *key = NULL;
    uint32_t next = 0;
    sock_t *sock = NULL;
    while (five_tuples_hash_iterate(&key, &sock, &next) >= 0) {
        if (sock->protocol != IPPROTO_UDP)
            continue;

        udp_payload_t *payloads[BURST_SIZE];
        size_t nr_send = 0;
        if ( (nr_send = rte_ring_mc_dequeue_burst(sock->sendbuf, (void **)&payloads, BURST_SIZE, NULL)) < 0)
            continue;

        for (size_t i = 0; i < nr_send; i++) {
            udp_payload_t *payload = payloads[i];
            uint8_t *dst_mac = get_dst_macaddr(payload->dip);
            if (!dst_mac) {
                send_arp_pkt(cfg, g_arp_request_mac, payload->dip, RTE_ARP_OP_REQUEST);
                rte_ring_mp_enqueue(sock->sendbuf, payload);
            } else {
                const unsigned total_length =
                    sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr) + payload->length;

                struct rte_mbuf *mbuf = rte_pktmbuf_alloc(cfg->mpool);
                if (!mbuf)
                    EEXIT("failed to alloc mbuf");

                mbuf->pkt_len = mbuf->data_len = total_length;
                create_udp_packet(mbuf, sock->mac, dst_mac, payload);
                en_out_ring_burst(cfg->ring, &mbuf, 1);
            }
        }

        for (size_t i = 0; i < nr_send; i++) {
            rte_free(payloads[i]->data);
            rte_free(payloads[i]);
        }
    }
}

