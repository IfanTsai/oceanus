#include "sock.h"
#include "dpdk.h"
#include <pthread.h>

#define ACCEPT_QUEUE_SIZE 65536

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

sock_table_t *get_sock_table_instance(void)
{
    static sock_table_t *sock_table = NULL;
    if (!sock_table) {
        pthread_mutex_lock(&mutex);

        if (!sock_table) {
            sock_table_t *tmp = (sock_table_t *)rte_malloc(NULL, sizeof(sock_table_t), 0);
            if (!tmp)
                EEXIT("failed to malloc sock table");

            tmp->five_tuples_sock_hash = create_hash("five tuples sock hash", SOCK_MAX_COUNT, FIVE_TUPLE_SIZE);
            if (!tmp->five_tuples_sock_hash)
                EEXIT("failed to create five tuples hash");

            tmp->fds_sock_hash = create_hash("fds sock hash", SOCK_MAX_COUNT, sizeof(int));
            if (!tmp->fds_sock_hash)
                EEXIT("failed to create five tuples hash");

            tmp->dports_listen_sock_hash = create_hash("listen hash", SOCK_MAX_COUNT, sizeof(uint16_t));
            if (!tmp->dports_listen_sock_hash)
                EEXIT("failed to create dports listen sock hash");

            tmp->dports_accept_sock_hash = create_hash("accept hash", SOCK_MAX_COUNT, sizeof(uint16_t));
            if (!tmp->dports_accept_sock_hash)
                EEXIT("failed to create dports accept sock hash");


            tmp->fds_eventpoll_hash = create_hash("fds eventpoll hash", SOCK_MAX_COUNT, sizeof(int));
            if (!tmp->fds_eventpoll_hash)
                EEXIT("failed to create five tuples hash");

            sock_table = tmp;
        }

        pthread_mutex_unlock(&mutex);
    }

    return sock_table;
}
