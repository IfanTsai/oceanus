#include "kni.h"
#include <rte_kni.h>
#include <rte_ethdev.h>

static inline int kni_config_network_if(uint16_t port_id, uint8_t if_up)
{
    if (!rte_eth_dev_is_valid_port(port_id)) {
        RTE_LOG(ERR, KNI, "Invalid port id %d\n", port_id);
        return -EINVAL;
    }

    RTE_LOG(INFO, KNI, "Configure network interface of %d %s\n", port_id, if_up ? "up" : "down");

    rte_eth_dev_stop(port_id);

    int ret = 0;
    if (if_up)
        ret = rte_eth_dev_start(port_id);

    if (ret < 0)
        RTE_LOG(ERR, KNI, "Failed to start port %d\n", port_id);

    return ret;
}

static inline struct rte_kni *alloc_kni(config_t *cfg)
{
    struct rte_kni_conf kni_conf = {
        .group_id = cfg->port_id,
        .mbuf_size = cfg->mbuf_size,
    };

    snprintf(kni_conf.name, RTE_KNI_NAMESIZE, "%s%u", cfg->kni_naem_prefix, cfg->port_id);
    memcpy(kni_conf.mac_addr, cfg->mac, RTE_ETHER_ADDR_LEN);
    rte_eth_dev_get_mtu(cfg->port_id, &kni_conf.mtu);

    struct rte_kni_ops kni_ops = {
        .port_id = cfg->port_id,
        .config_network_if = kni_config_network_if,
    };

    return rte_kni_alloc(cfg->mpool, &kni_conf, &kni_ops);
}

struct rte_kni *init_kni(config_t *cfg)
{
    if (rte_kni_init(cfg->port_id) < 0)
        return NULL;

    return alloc_kni(cfg);
}
