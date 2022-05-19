#ifndef __ARP_TABLE_H__
#define __ARP_TABLE_H__

#include "dpdk.h"
#include "hash.h"
#include <rte_ether.h>
#include <rte_malloc.h>
#include <rte_hash.h>
#include <arpa/inet.h>

#define ARP
#define RTE_LOGTYPE_ARP RTE_LOGTYPE_USER1


#define ARP_ENTRY_TYPE_DYNAMIC    0
#define ARP_ENTRY_TYPE_STATIC     1

#define ARP_TABLE_ENTRIES         10240
#define ARP_ENTRY_TIMEOUT         60

typedef struct arp_entry {
    uint32_t ip;
    uint8_t hwaddr[RTE_ETHER_ADDR_LEN];
    uint8_t type;
    uint64_t timeout;
} arp_entry_t;

typedef struct arp_table {
    struct rte_hash *hash;
} arp_table_t;

arp_table_t *get_arp_table_instance(void);

static inline arp_entry_t *get_arp_entry(uint32_t ip)
{
    arp_table_t *arp_table = get_arp_table_instance();

    arp_entry_t *arp_entry = NULL;
    hash_lookup(arp_table->hash, &ip, (void **)&arp_entry);

    return arp_entry;
}

static inline uint8_t *get_dst_macaddr(uint32_t ip)
{
    arp_entry_t *arp_entry = get_arp_entry(ip);

    if (!arp_entry)
        return NULL;

    return arp_entry->hwaddr;
}

static inline int32_t arp_entry_iterate(uint32_t *key, uint32_t *next, arp_entry_t **entry)
{
    arp_table_t *arp_table = get_arp_table_instance();

    return hash_iterate(arp_table->hash, (const void **)&key, (void **)entry, next);
}

static inline void print_arp_entry(arp_entry_t *entry)
{
    struct in_addr addr = {
        .s_addr = entry->ip,
    };

    char buf[RTE_ETHER_ADDR_FMT_SIZE];
    rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE, (struct rte_ether_addr *)entry->hwaddr);

    printf("%-15s %-20s %d\n", inet_ntoa(addr), buf, entry->type);
}

static inline void print_arp_table(void)
{
    printf("        arp entry count: %d\n", hash_count(get_arp_table_instance()->hash));
    printf("%-15s %-20s %s\n", "ip", "mac", "type");

    uint32_t key = 0, next = 0;
    arp_entry_t *entry;
    while (arp_entry_iterate(&key, &next, &entry) >= 0)
        print_arp_entry(entry);
    printf("-------------------------------------------\n");

}

static inline void add_arp_entry(uint32_t ip, uint8_t *mac)
{
    arp_entry_t *arp_entry = get_arp_entry(ip);
    if (!arp_entry) {
        arp_entry = rte_malloc(NULL, sizeof(arp_entry_t), 0);
        if (!arp_entry) {
            RTE_LOG(WARNING, ARP, "failed to alloc mbuf to add arp entry");
            return;
        }

        rte_memcpy(arp_entry->hwaddr, mac, RTE_ETHER_ADDR_LEN);
        arp_entry->ip = ip;
        arp_entry->type = ARP_ENTRY_TYPE_DYNAMIC;
        arp_entry->timeout = rte_get_tsc_cycles() / rte_get_tsc_hz() + ARP_ENTRY_TIMEOUT;

        arp_table_t *arp_table = get_arp_table_instance();
        hash_add(arp_table->hash, &ip, arp_entry);

        //print_arp_table();
    } else {
        // update arp entry timeout
        arp_entry->timeout = rte_get_tsc_cycles() / rte_get_tsc_hz() + ARP_ENTRY_TIMEOUT;
    }
}

static inline int32_t del_arp_entry(uint32_t ip)
{
    arp_table_t *arp_table = get_arp_table_instance();
    arp_entry_t *arp_entry = get_arp_entry(ip);
    if (!arp_entry)
        return 0;

    int32_t ret = hash_del(arp_table->hash, &ip);
    rte_free(arp_entry);

    return ret;
}

#endif
