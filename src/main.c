#include "config.h"
#include "dpdk.h"
#include "ring.h"
#include "netdev.h"
#include "arp.h"
#include <rte_ethdev.h>
#include <rte_kni.h>

config_t g_cfg;

static inline void init_config(int argc, char *argv[])
{
    g_cfg.argc = argc;
    g_cfg.argv = argv;
    g_cfg.port_id = 0;
    g_cfg.mpool_name = "mbuf pool";
    g_cfg.mpool_size = 4096 - 1;
    g_cfg.mbuf_size = RTE_MBUF_DEFAULT_BUF_SIZE;
    g_cfg.burst_size = 1024;
    g_cfg.kni_naem_prefix = "vEth";
    g_cfg.ring_name = "io ring";
    g_cfg.ring_size = 1024;
    g_cfg.ip = inet_addr("192.168.18.115");
}

static inline void init_io_ring(config_t *cfg)
{
    if ( !(cfg->ring = init_ring(cfg->ring_name, cfg->ring_size)) )
        EEXIT("failed to init io ring");
}

int main(int argc, char *argv[])
{
    init_config(argc, argv);
    init_dpdk(&g_cfg);
    init_io_ring(&g_cfg);

    unsigned int lcore_id = rte_lcore_id();

    struct rte_timer arp_request_timer;
    netdev_init_arp_update_timer(&g_cfg, &arp_request_timer, lcore_id);

    lcore_id = rte_get_next_lcore(lcore_id, 1, 0);
    rte_eal_remote_launch(netdev_process_pkt_loop, &g_cfg, lcore_id);

    netdev_rx_tx_loop(&g_cfg);

    return 0;
}

