#include "edd.h"
#include <math.h>

// edd: Entropy DDoS Detector

static uint32_t set_bits_arr[DDOS_WINDOW_SIZE];
static uint32_t tot_bits_arr[DDOS_WINDOW_SIZE];
static double   entropy_arr[DDOS_WINDOW_SIZE];
static uint32_t ddos_window_index;

// ref:
// http://ivandemarino.me/2010/01/07/count-bits-set-in-parallel/
// http://graphics.stanford.edu/~seander/bithacks.html#CountBitsSetParallel
static uint32_t count_set_bits(const uint8_t *packet, const uint32_t len)
{
    uint32_t v; // count bits set in this (32-bit value)
    uint32_t c; // store the total here per 4bytes
    uint32_t set_bits = 0; // store the total here
    static const int S[] = {1, 2, 4, 8, 16}; // Magic Binary Numbers
    static const int B[] = {0x55555555, 0x33333333, 0x0F0F0F0F, 0x00FF00FF, 0x0000FFFF};

    const uint32_t *ptr = (const uint32_t *)packet;
    const uint32_t *end = (const uint32_t *)(packet+ len);

    while (ptr < end) {
        v = *ptr++;
        c = v - ((v >> S[0]) & B[0]);
        c = ((c >> S[1]) & B[1]) + (c & B[1]);
        c = ((c >> S[2]) + c) & B[2];
        c = ((c >> S[3]) + c) & B[3];
        c = ((c >> S[4]) + c) & B[4];

        set_bits += c;
    }

    return set_bits;
}

static inline double calc_entropy(const double set_bits, const double tot_bits)
{
    return (-set_bits) * (log2(set_bits) - log2(tot_bits))
        - (tot_bits - set_bits) * (log2(tot_bits - set_bits) - log2(tot_bits))
        + log2(tot_bits);
}

bool detect_ddos(const uint8_t *packet, const uint32_t len)
{
    static bool ddos_status = false;
    uint32_t set_bits = count_set_bits(packet, len);
    uint32_t tot_bits = len * 8;

    set_bits_arr[ddos_window_index % DDOS_WINDOW_SIZE] = set_bits;
    tot_bits_arr[ddos_window_index % DDOS_WINDOW_SIZE] = tot_bits;
    entropy_arr[ddos_window_index  % DDOS_WINDOW_SIZE] = calc_entropy(set_bits, tot_bits);

    if (ddos_window_index++ < DDOS_WINDOW_SIZE)
        return ddos_status;

    ddos_window_index = ddos_window_index % DDOS_WINDOW_SIZE + DDOS_WINDOW_SIZE;

    uint32_t sum_set_bits = 0, sum_tot_bits = 0;
    double sum_entropy = 0.0;
    for (int i = 0; i < DDOS_WINDOW_SIZE; i++) {
        sum_set_bits += set_bits_arr[i];
        sum_tot_bits += tot_bits_arr[i];
        sum_entropy += entropy_arr[i];
    }

    double entropy = calc_entropy(sum_set_bits, sum_tot_bits);
    if (sum_entropy - entropy > DDOS_TRESH) {
        if (ddos_status)
            return ddos_status;

        ddos_status = true;
        RTE_LOG(ALERT, DDOS, "ddos attack!!! entropy(%f) < total_entropy(%f) over %u bits\n", entropy, sum_entropy, sum_tot_bits);
    } else {
        if (!ddos_status)
            return ddos_status;

        ddos_status = false;
        RTE_LOG(NOTICE, DDOS, "no news. entropy(%f) >= total_entropy(%f) over %u bits\n", entropy, sum_entropy, sum_tot_bits);
    }

    return ddos_status;
}

bool detect_ddos_burst(struct rte_mbuf **mbufs, const uint16_t nb_pkts)
{
    for (uint16_t i = 0; i < nb_pkts; i++)
        if (detect_ddos(rte_pktmbuf_mtod(mbufs[i], uint8_t *), mbufs[i]->buf_len))
            return true;

    return false;
}
