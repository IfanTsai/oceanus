#ifndef __UTIL_H__
#define __UTIL_H__

#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>

static inline void swap_mac(struct rte_ether_hdr *ethdr)
{
    uint8_t tmp_mac[RTE_ETHER_ADDR_LEN];

    rte_memcpy(tmp_mac, &ethdr->d_addr, RTE_ETHER_ADDR_LEN);
    rte_memcpy(&ethdr->d_addr, &ethdr->s_addr, RTE_ETHER_ADDR_LEN);
    rte_memcpy(&ethdr->s_addr, tmp_mac, RTE_ETHER_ADDR_LEN);
}

static inline void swap_ip(struct rte_ipv4_hdr *iphdr)
{
    uint32_t tmp_ip;

    rte_memcpy(&tmp_ip, &iphdr->src_addr, sizeof(tmp_ip));
    rte_memcpy(&iphdr->src_addr, &iphdr->dst_addr, sizeof(tmp_ip));
    rte_memcpy(&iphdr->dst_addr, &tmp_ip, sizeof(tmp_ip));
}

static inline void swap_port(struct rte_tcp_hdr *tcphdr)
{
    uint16_t tmp_port;

    rte_memcpy(&tmp_port, &tcphdr->src_port, sizeof(tmp_port));
    rte_memcpy(&tcphdr->src_port, &tcphdr->dst_port, sizeof(tmp_port));
    rte_memcpy(&tcphdr->dst_port, &tmp_port, sizeof(tmp_port));
}

#endif

