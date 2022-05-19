#ifndef __NETDEV_H__
#define __NETDEV_H__

#include "config.h"
#include <rte_timer.h>

int  netdev_rx_tx_loop(void *arg);
int  netdev_process_pkt_loop(void *arg);
void netdev_tx_commit(config_t *cfg, struct rte_mbuf **mbuf);

#endif
