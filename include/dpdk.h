#ifndef __DPDK_H__
#define __DPDK_H__

#include "config.h"
#include <rte_ether.h>

#define EEXIT(fmt, ...) \
        rte_exit(EXIT_FAILURE, "[%s:%s:%d] "fmt"\n", __FILE__, __func__, __LINE__, ##__VA_ARGS__)

void init_dpdk(config_t *cfg);

#endif
