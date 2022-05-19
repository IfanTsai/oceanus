#ifndef __MBUF_H__
#define __MBUF_H__

#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_arp.h>
#include <rte_icmp.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>

#define mbuf_ethdr(m)   \
        rte_pktmbuf_mtod(m, struct rte_ether_hdr *)

#define mbuf_arphdr(m)  \
        rte_pktmbuf_mtod_offset(m, struct rte_arp_hdr *, sizeof(struct rte_ether_hdr))

#define mbuf_iphdr(m)   \
        rte_pktmbuf_mtod_offset(m, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr))

#define mbuf_icmphdr(m) \
        rte_pktmbuf_mtod_offset(m, struct rte_icmp_hdr *, sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr))

#define mbuf_tcphdr(m)  \
        rte_pktmbuf_mtod_offset(m, struct rte_tcp_hdr *, sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr))

#define mbuf_udphdr(m) (struct rte_udp_hdr*)mbuf_tcphdr(m)

#endif
