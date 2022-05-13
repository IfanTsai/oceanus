#ifndef __NETDEV_H__
#define __NETDEV_H__

#include "config.h"
#include <rte_timer.h>

void netdev_tx_commit(config_t *cfg, struct rte_mbuf **mbuf);
void netdev_rx_tx_loop(config_t *cfg);
int  netdev_process_pkt_loop(void *arg);
void netdev_init_arp_update_timer(config_t *cfg, struct rte_timer *timer, unsigned lcore_id);

#endif
