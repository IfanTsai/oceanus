#include "netdev.h"
#include "mbuf.h"
#include "config.h"
#include "ring.h"
#include "arp.h"
#include "arp_table.h"
#include "icmp.h"
#include <rte_ethdev.h>
#include <rte_ip.h>
#include <rte_kni.h>
#include <stdio.h>

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
            break;

        case IPPROTO_TCP:
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
}

static void arp_update_timer_cb(__attribute__((unused)) struct rte_timer *tim, void *arg)
{
    config_t *cfg = (config_t *)arg;

    uint64_t cur_tsc = rte_get_tsc_cycles();
    uint32_t key = 0, next = 0;
    arp_entry_t *entry;
    while (arp_entry_iterate(&key, &next, &entry) >= 0) {
        // reflush entry if timeout
        if (cur_tsc < entry->timeout * rte_get_timer_hz()) {
            del_arp_entry(entry->ip);
            send_arp_pkt(cfg, entry->hwaddr, entry->ip, RTE_ARP_OP_REQUEST);
        }
    }
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

        // redeive
        uint16_t nr_recvd = rte_eth_rx_burst(cfg->port_id, 0, mbufs, BURST_SIZE);
        if (nr_recvd > BURST_SIZE)
            EEXIT("too many packets, %d", nr_recvd);

        if (nr_recvd > 0)
            en_in_ring_burst(cfg->ring, mbufs, nr_recvd);

        // send
        uint16_t nr_send = de_out_ring_burst(cfg->ring, mbufs, BURST_SIZE);
        if (nr_send > 0) {
            rte_eth_tx_burst(cfg->port_id, 0, mbufs, nr_send);
            rte_pktmbuf_free_bulk(mbufs, nr_send);
        }
    }
}

void netdev_tx_commit(config_t *cfg, struct rte_mbuf **mbuf)
{
    en_out_ring_burst(cfg->ring, mbuf, 1);
}

void netdev_init_arp_update_timer(config_t *cfg, struct rte_timer *timer, unsigned lcore_id)
{
    // initialize RTE timer library
    rte_timer_subsystem_init();

    // initialize timer structures
    rte_timer_init(timer);

    // load timer, every second, on lcore specified lcore_id, reloaded automatically
    rte_timer_reset(timer, rte_get_timer_hz(), PERIODICAL, lcore_id, arp_update_timer_cb, cfg);
}

