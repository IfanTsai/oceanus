#ifndef __CONFIG_H__
#define __CONFIG_H__

#include "ring.h"
#include "sock.h"
#include <rte_ether.h>
#include <arpa/inet.h>

#define BURST_SIZE 32

typedef struct {
	int argc;
	char **argv;
	uint16_t port_id;
	const char *mpool_name;
	uint32_t mpool_size;
	uint32_t mbuf_size;
	uint32_t burst_size;
	const char *kni_naem_prefix;
	const char *ring_name;
	uint32_t ring_size;
	in_addr_t ip;

	uint8_t mac[RTE_ETHER_ADDR_LEN];
	struct rte_mempool *mpool;
	struct rte_kni *kni;
	ring_t *ring;
} config_t;

#endif
