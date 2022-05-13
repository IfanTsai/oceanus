#include "arp.h"
#include "arp_table.h"
#include "netdev.h"
#include "mbuf.h"

static uint8_t g_arp_request_mac[RTE_ETHER_ADDR_LEN] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

static inline void
process_arp_request(config_t *cfg, struct rte_arp_hdr *arphdr, struct rte_ether_hdr *ethdr)
{
    // set arp type is reply
    arphdr->arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REPLY);

    // modify ether mac address
    rte_memcpy(ethdr->d_addr.addr_bytes, ethdr->s_addr.addr_bytes, RTE_ETHER_ADDR_LEN);
    rte_memcpy(ethdr->s_addr.addr_bytes, cfg->mac, RTE_ETHER_ADDR_LEN);

    // modify arp mac address
    rte_memcpy(arphdr->arp_data.arp_tha.addr_bytes, arphdr->arp_data.arp_sha.addr_bytes, RTE_ETHER_ADDR_LEN);
    rte_memcpy(arphdr->arp_data.arp_sha.addr_bytes, cfg->mac, RTE_ETHER_ADDR_LEN);

    // modify arp ip address
    arphdr->arp_data.arp_tip = arphdr->arp_data.arp_sip;
    arphdr->arp_data.arp_sip = cfg->ip;
}

static inline void process_arp_reply(struct rte_arp_hdr *arphdr)
{
    // add arp entry to arp table
    add_arp_entry(arphdr->arp_data.arp_sip, arphdr->arp_data.arp_sha.addr_bytes);
}

static void
create_arp_pkt(uint8_t *pkt_data,
        uint8_t *src_mac, uint8_t *dst_mac, uint32_t src_ip, uint32_t dst_ip, uint16_t arp_opcode)
{
    struct rte_ether_hdr *ethdr = (struct rte_ether_hdr *)pkt_data;
    rte_memcpy(ethdr->s_addr.addr_bytes, src_mac, RTE_ETHER_ADDR_LEN);
    rte_memcpy(ethdr->d_addr.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);
    ethdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP);

    struct rte_arp_hdr *arphdr = (struct rte_arp_hdr *)(ethdr + 1);
    arphdr->arp_hardware = rte_cpu_to_be_16(RTE_ARP_HRD_ETHER);
    arphdr->arp_protocol = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
    arphdr->arp_hlen = RTE_ETHER_ADDR_LEN;
    arphdr->arp_plen = sizeof(uint32_t);
    arphdr->arp_opcode = rte_cpu_to_be_16(arp_opcode);

    rte_memcpy(arphdr->arp_data.arp_sha.addr_bytes, src_mac, RTE_ETHER_ADDR_LEN);
    if (!memcmp(dst_mac, g_arp_request_mac, RTE_ETHER_ADDR_LEN)) {
        uint8_t mac[RTE_ETHER_ADDR_LEN] = { 0 };
        rte_memcpy(arphdr->arp_data.arp_tha.addr_bytes, mac, RTE_ETHER_ADDR_LEN);
    } else {
        rte_memcpy(arphdr->arp_data.arp_tha.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);
    }

    arphdr->arp_data.arp_sip = src_ip;
    arphdr->arp_data.arp_tip = dst_ip;
}

int process_arp_pkt(config_t *cfg, struct rte_mbuf *mbuf)
{
    struct rte_ether_hdr *ethdr = mbuf_ethdr(mbuf);
    struct rte_arp_hdr *arphdr = mbuf_arphdr(mbuf);

    if (arphdr->arp_data.arp_tip != cfg->ip)
        return -1;

    switch (rte_be_to_cpu_16(arphdr->arp_opcode)) {
    case RTE_ARP_OP_REQUEST: {
        process_arp_request(cfg, arphdr, ethdr);
        // zero-copy process icmp request mbuf
        netdev_tx_commit(cfg, &mbuf);
        break;
    }
    case RTE_ARP_OP_REPLY:
        process_arp_reply(arphdr);
        return -1;
    }

    return 0;
}

void send_arp_pkt(config_t *cfg, uint8_t *dst_mac, uint32_t dst_ip, uint16_t arp_opcode)
{
    const unsigned total_length = sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr);

    struct rte_mbuf *mbuf = rte_pktmbuf_alloc(cfg->mpool);
    if (!mbuf) {
        RTE_LOG(WARNING, ARP, "failed to alloc mbuf to send arp\n");
        return;
    }

    mbuf->pkt_len = mbuf->data_len = total_length;

    uint8_t *pkt_data = rte_pktmbuf_mtod(mbuf, uint8_t *);
    create_arp_pkt(pkt_data, cfg->mac, dst_mac, cfg->ip, dst_ip, arp_opcode);

    netdev_tx_commit(cfg, &mbuf);
}

