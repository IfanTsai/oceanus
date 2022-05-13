#include "dpdk.h"
#include "kni.h"
#include <rte_ethdev.h>

static inline void init_port(config_t *cfg)
{
    // check if eth device is available
    if (rte_eth_dev_count_avail() == 0)
        EEXIT("eth device is not available");

    struct rte_eth_conf eth_conf = {};
    if (rte_eth_dev_configure(cfg->port_id, 1, 1, &eth_conf) < 0)
        EEXIT("failed to configure eth, port: %d", cfg->port_id);

    int socket_id = rte_eth_dev_socket_id(cfg->port_id);

    // initialize rx queue
    if (rte_eth_rx_queue_setup(cfg->port_id, 0, 128, socket_id, NULL, cfg->mpool) < 0)
        EEXIT("failed to setup rx queue");

    // initialize tx queue
    if (rte_eth_tx_queue_setup(cfg->port_id, 0, 512, socket_id, NULL) < 0)
        EEXIT("failed to setup tx queue");

    // start eth device
    if (rte_eth_dev_start(cfg->port_id) < 0)
        EEXIT("failed to start eth dev, port: %d", cfg->port_id);

    // enable promiscuous
    rte_eth_promiscuous_enable(cfg->port_id);
}

void init_dpdk(config_t *cfg)
{
    // initialize Environment Abstraction Layer (EAL)
    if (rte_eal_init(cfg->argc, cfg->argv) < 0)
        EEXIT("failed to init EAL");

    // get mac address
    rte_eth_macaddr_get(cfg->port_id, (struct rte_ether_addr *)cfg->mac);

    // initialize memory pool
    if ( !(cfg->mpool = rte_pktmbuf_pool_create(cfg->mpool_name, cfg->mpool_size, 0, 0, cfg->mbuf_size, rte_socket_id())) )
        EEXIT("failed to create memory pool");

    // initialize port
   init_port(cfg);

    // initialize kni
    if ( !(cfg->kni = init_kni(cfg)) )
	EEXIT("failed to init kni");
}
