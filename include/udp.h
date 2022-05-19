#ifndef __UDP_H__
#define __UDP_H__

#include "config.h"

typedef struct {
    uint32_t sip, dip;
    uint16_t sport, dport;
    unsigned char *data;
    uint16_t length;
} udp_payload_t;

int process_udp_pkt(config_t *cfg, struct rte_mbuf *mbuf);
void send_udp_pkts(config_t *cfg);

#endif
