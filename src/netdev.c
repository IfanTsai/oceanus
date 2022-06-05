#include "netdev.h"
#include "mbuf.h"
#include "config.h"
#include "ring.h"
#include "arp.h"
#include "arp_table.h"
#include "icmp.h"
#include "udp.h"
#include "tcp.h"
#include "sock.h"
#include "edd.h"
#include <rte_ethdev.h>
#include <rte_kni.h>

static void process_recv_pkt(config_t *cfg, struct rte_mbuf *mbuf)
{
    struct rte_ether_hdr *ethdr = mbuf_ethdr(mbuf);
    struct rte_ipv4_hdr *iphdr = mbuf_iphdr(mbuf);
    int ret = 1;

    switch (rte_be_to_cpu_16(ethdr->ether_type)) {
    case RTE_ETHER_TYPE_ARP:
        ret = process_arp_pkt(cfg, mbuf);
        break;

    case RTE_ETHER_TYPE_IPV4:
        // add arp entry to arp table
        add_arp_entry(iphdr->src_addr, ethdr->s_addr.addr_bytes);

        switch (iphdr->next_proto_id) {
        case IPPROTO_ICMP:
            ret = process_icmp_pkt(cfg, mbuf);
            break;

        case IPPROTO_UDP:
            ret = process_udp_pkt(cfg, mbuf);
            break;

        case IPPROTO_TCP:
            ret = process_tcp_pkt(cfg, mbuf);
            break;
        }

        break;
    }

    if (ret == 1) {
        rte_kni_tx_burst(cfg->kni, &mbuf, 1);
        rte_kni_handle_request(cfg->kni);
    }

    if (ret != 0)
        rte_pktmbuf_free(mbuf);
}


static void process_recv_pkts(config_t *cfg)
{
    struct rte_mbuf *mbufs[BURST_SIZE];
    unsigned int nr_recvd = de_in_ring_burst(cfg->ring, mbufs, BURST_SIZE);
    for (unsigned int i = 0; i < nr_recvd; i++)
        process_recv_pkt(cfg, mbufs[i]);
}

static inline void process_send_pkts(config_t *cfg)
{
    send_udp_pkts(cfg);
    send_tcp_pkts(cfg);
}

static inline void process_timer(void)
{
    static uint64_t prev_tsc = 0;

    // check timer
    uint64_t cur_tsc = rte_get_tsc_cycles();
    uint64_t diff_tsc = cur_tsc - prev_tsc;
    if (diff_tsc > ARP_ENTRY_TIMEOUT * rte_get_tsc_hz()) {
        rte_timer_manage();    // call timer cb
        prev_tsc = cur_tsc;
    }
}

int netdev_process_pkt_loop(void *arg)
{
    config_t *cfg = (config_t *)arg;

    for (;;) {
        process_recv_pkts(cfg);
        process_send_pkts(cfg);
    }

    return 0;
}

int netdev_rx_tx_loop(void *arg)
{
    config_t *cfg = (config_t *)arg;
    struct rte_mbuf *mbufs[BURST_SIZE];
    for (;;) {
        // timer
        process_timer();

        // receive
        uint16_t nr_recvd = rte_eth_rx_burst(cfg->port_id, 0, mbufs, BURST_SIZE);
        if (nr_recvd > BURST_SIZE)
            EEXIT("too many packets, %d", nr_recvd);

        if (nr_recvd > 0) {
            if (detect_ddos_burst(mbufs, nr_recvd)) {
                for (uint16_t i = 0; i < nr_recvd; i++)
                    rte_pktmbuf_free(mbufs[i]);
                continue;
            }

            en_in_ring_burst(cfg->ring, mbufs, nr_recvd);
        }

        // send
        uint16_t nr_send = de_out_ring_burst(cfg->ring, mbufs, BURST_SIZE);
        if (nr_send > 0) {
            rte_eth_tx_burst(cfg->port_id, 0, mbufs, nr_send);

            for (uint16_t i = 0; i < nr_send; i++)
                rte_pktmbuf_free(mbufs[i]);
        }
    }
}

void netdev_tx_commit(config_t *cfg, struct rte_mbuf **mbuf)
{
    en_out_ring_burst(cfg->ring, mbuf, 1);
}

