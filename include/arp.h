#ifndef __ARP_H__
#define __ARP_H__

#include "config.h"
#include <rte_arp.h>
#include <rte_timer.h>

extern uint8_t g_arp_request_mac[RTE_ETHER_ADDR_LEN];

int process_arp_pkt(config_t *cfg, struct rte_mbuf *mbuf);
void send_arp_pkt(config_t *cfg, uint8_t *dst_mac, uint32_t dst_ip, uint16_t arp_opcode);
void init_arp_update_timer(config_t *cfg, struct rte_timer *timer, unsigned lcore_id);

#endif
