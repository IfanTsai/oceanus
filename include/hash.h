#ifndef __HASH_H__
#define __HASH_H__

#include <rte_lcore.h>
#include <rte_hash.h>
#include <rte_jhash.h>

static inline uint32_t jhash(const void *key, uint32_t length)
{
	return rte_jhash(key, length, 0);
}

static inline struct rte_hash *create_hash(const char *name, uint32_t entries, uint32_t key_size)
{
    struct rte_hash_parameters params = {
        .name = name,
        .entries = entries,
        .key_len = key_size,
        .hash_func = rte_jhash,
        .hash_func_init_val = 0,
        .socket_id = rte_socket_id(),
        .extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY,
    };

    return rte_hash_create(&params);
}

static inline int hash_add(const struct rte_hash *h, const void *key, void *data)
{
    return rte_hash_add_key_data(h, key, data);
}

static inline int hash_del(const struct rte_hash *h, const void *key)
{
    return rte_hash_del_key(h, key);
}

static inline int hash_lookup(const struct rte_hash *h, const void *key, void **data)
{
    return rte_hash_lookup_data(h, key, data);
}

static inline int32_t hash_iterate(const struct rte_hash *h, const void **key, void **data, uint32_t *next)
{
    return rte_hash_iterate(h, key, data, next);
}

static inline int32_t hash_count(const struct rte_hash *h)
{
    return rte_hash_count(h);
}

#endif

