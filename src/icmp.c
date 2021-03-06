#pragma GCC diagnostic ignored "-Waddress-of-packed-member"
#include "icmp.h"
#include "netdev.h"
#include "util.h"
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_icmp.h>

static uint16_t icmp_cksum(struct rte_ipv4_hdr *iphdr, struct rte_icmp_hdr *icmphdr)
{
    uint16_t *addr = (uint16_t *)icmphdr;
    int count = rte_be_to_cpu_16(iphdr->total_length) - sizeof(*iphdr);

    register long sum = 0;

    while (count > 1) {
        sum += *(unsigned short *)addr++;
        count -= 2;
    }

    if (count > 0)
        sum += *(unsigned char *)addr;

    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);

    return ~sum;
}

int process_icmp_pkt(config_t *cfg, struct rte_mbuf *mbuf)
{
    struct rte_ether_hdr *ethdr = mbuf_ethdr(mbuf);
    struct rte_ipv4_hdr *iphdr = mbuf_iphdr(mbuf);
    struct rte_icmp_hdr *icmphdr = mbuf_icmphdr(mbuf);

    if (icmphdr->icmp_type != RTE_IP_ICMP_ECHO_REQUEST)
        return -1;

    // swap source and destination value
    swap_mac(ethdr);
    swap_ip(iphdr);

    /**
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |    Type       |     Code      |            Checksum           |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |           Identifier          |       Sequence Number         |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * | Data ...
     * +-+-+-+-+-
     */
    // packet ICMP Reply Message
    icmphdr->icmp_type = RTE_IP_ICMP_ECHO_REPLY;
    icmphdr->icmp_code = 0;
    //icmphdr->icmp_ident = icmphdr->icmp_ident;
    //icmphdr->icmp_seq_nb = icmphdr->icmp_seq_nb;

    // set icmp checksum
    icmphdr->icmp_cksum = 0;
    icmphdr->icmp_cksum = icmp_cksum(iphdr, icmphdr);

    // zero-copy process icmp request mbuf
    netdev_tx_commit(cfg, &mbuf);

    return 0;
}
