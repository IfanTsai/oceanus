#include "config.h"
#include "dpdk.h"
#include "ring.h"
#include "netdev.h"
#include "arp.h"
#include "oceanus.h"
#include "api.h"
#include <rte_ethdev.h>
#include <rte_kni.h>

#define IP              "192.168.18.115"
#define RING_SIZE       1024
#define POOL_SIZE       (4096 - 1)
#define PORT_ID         0
#define KNI_NAME_PREFIX "vEth"

static config_t g_cfg;

static inline void init_config(int argc, char *argv[])
{
    g_cfg.argc = argc;
    g_cfg.argv = argv;
    g_cfg.port_id = PORT_ID;
    g_cfg.mpool_name = " config mbuf pool";
    g_cfg.mpool_size = POOL_SIZE;
    g_cfg.mbuf_size = RTE_MBUF_DEFAULT_BUF_SIZE;
    g_cfg.burst_size = BURST_SIZE;
    g_cfg.kni_naem_prefix = KNI_NAME_PREFIX;
    g_cfg.ring_name = "config io ring";
    g_cfg.ring_size = RING_SIZE;
    g_cfg.ip = inet_addr(IP);
}

static inline void init_io_ring(config_t *cfg)
{
    if ( !(cfg->ring = init_ring(cfg->ring_name, cfg->ring_size)) )
        EEXIT("failed to init io ring");
}

void start_oceanus(int argc, char *argv[])
{
    init_config(argc, argv);
    init_dpdk(&g_cfg);
    init_io_ring(&g_cfg);
    init_api(&g_cfg);

    unsigned int lcore_id = rte_get_next_lcore(rte_lcore_id(), 1, 0);
    rte_eal_remote_launch(netdev_rx_tx_loop, &g_cfg, lcore_id);

    struct rte_timer *arp_request_timer = rte_malloc(NULL, sizeof(struct rte_timer), 0);
    init_arp_update_timer(&g_cfg, arp_request_timer, lcore_id);

    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
        rte_eal_remote_launch(netdev_process_pkt_loop, &g_cfg, lcore_id);
    }
}

int wait_oceanus(void)
{
    rte_eal_mp_wait_lcore();

    return rte_eal_cleanup();
}

in_addr_t get_local_ip(void)
{
    return g_cfg.ip;
}
