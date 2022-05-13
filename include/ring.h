#ifndef __RING_H__
#define __RING_H__

#include <rte_ring.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>

typedef struct {
    struct rte_ring *in;
    struct rte_ring *out;
} ring_t;

/**
 * initalize in ring and out ring
 */
static inline ring_t *init_ring(const char *name, uint32_t ring_size)
{
    ring_t *ring = rte_zmalloc(NULL, sizeof(ring_t), 0);
    if (!ring)
        return NULL;

    char ring_name[1024] = { 0 };
    snprintf(ring_name, sizeof(ring_name), "%s in", name);
    ring->in = rte_ring_create(ring_name, ring_size, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (!ring->in)
        goto err_create_in_ring;

    snprintf(ring_name, sizeof(ring_name), "%s out", name);
    ring->out = rte_ring_create(ring_name, ring_size, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (!ring->out)
        goto err_create_out_ring;

    return ring;

err_create_out_ring:
    rte_ring_free(ring->in);
err_create_in_ring:
    rte_free(ring);

    return NULL;
}

/**
 * free in ring and out ring
 */
static inline void free_ring(ring_t *ring)
{
    rte_ring_free(ring->out);
    rte_ring_free(ring->in);
    rte_free(ring);
}

/**
 * enqueue serverl mbufs to the in ring buf (multi-producers safe)
 */
static inline void en_in_ring_burst(ring_t *ring, struct rte_mbuf **mbufs, unsigned n)
{
    rte_ring_mp_enqueue_burst(ring->in, (void **)mbufs, n, NULL);
}

/**
 * enqueue serverl mbufs to the out ring buf (multi-producers safe)
 */
static inline void en_out_ring_burst(ring_t *ring, struct rte_mbuf **mbufs, unsigned n)
{
    rte_ring_mp_enqueue_burst(ring->out, (void **)mbufs, n, NULL);
}


/**
 * denqueue serverl mbufs from the in ring buf (multi-consumer safe)
 */
static inline unsigned int de_in_ring_burst(ring_t *ring, struct rte_mbuf **mbufs, unsigned n)
{
    return rte_ring_mc_dequeue_burst(ring->in, (void **)mbufs, n, NULL);
}

/**
 * denqueue serverl mbufs from the out ring buf (multi-consumer safe)
 */
static inline unsigned int de_out_ring_burst(ring_t *ring, struct rte_mbuf **mbufs, unsigned n)
{
    return rte_ring_mc_dequeue_burst(ring->out, (void **)mbufs, n, NULL);
}

#endif
