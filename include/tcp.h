#ifndef __TCP_H__
#define __TCP_H__

#include "config.h"

#define TCP_OPTION_INTS    10
#define TCP_MAX_SEQ        UINT_MAX
#define TCP_INITIAL_WINDOW 14600

typedef enum {
    TCP_STATUS_CLOSED = 0,
    TCP_STATUS_LISTEN,
    TCP_STATUS_SYN_RCVD,
    TCP_STATUS_SYN_SENT,
    TCP_STATUS_ESTABLISHED,
    TCP_STATUS_FIN_WAIT1,
    TCP_STATUS_FIN_WAIT2,
    TCP_STATUS_CLOSING,
    TCP_STATUS_TIME_WAIT,
    TCP_STATUS_CLOSE_WAIT,
    TCP_STATUS_LAST_ACK,
} tcp_status_t;

typedef struct {
    uint16_t sport;
    uint16_t dport;
    uint32_t seq;
    uint32_t ack;
    uint8_t  data_off;
    uint8_t  flags;
    uint16_t win;
    uint16_t cksum;
    uint16_t urp;
    uint32_t option[TCP_OPTION_INTS];
    uint8_t  option_len;
    uint8_t *data;
    uint32_t length;
} tcp_fragment_t;

void send_tcp_pkts(config_t *cfg);
int process_tcp_pkt(config_t *cfg, struct rte_mbuf *mbuf);

#endif
