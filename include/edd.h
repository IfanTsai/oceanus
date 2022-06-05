#ifndef _EDD_H__
#define _EDD_H__

#include <rte_log.h>
#include <rte_mbuf.h>
#include <stdbool.h>

#define DDOS
#define RTE_LOGTYPE_DDOS RTE_LOGTYPE_USER2

#define DDOS_WINDOW_SIZE 256
#define DDOS_TRESH 2400.0

bool detect_ddos(const uint8_t *packet, const uint32_t len);
bool detect_ddos_burst(struct rte_mbuf **mbufs, const uint16_t nb_pkts);

#endif
