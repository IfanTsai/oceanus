#ifndef __ICMP_H__
#define __ICMP_H__

#include "config.h"
#include "mbuf.h"

int process_icmp_pkt(config_t *cfg, struct rte_mbuf *mbuf);

#endif
