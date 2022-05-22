#include "sock.h"
#include "dpdk.h"
#include <pthread.h>

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

            tmp->five_tuples_hash = create_hash("five tuples hash", SOCK_MAX_COUNT, FIVE_TUPLE_SIZE);
            if (!tmp->five_tuples_hash)
                EEXIT("failed to create five tuples hash");

            tmp->fds_hash = create_hash("fds hash", SOCK_MAX_COUNT, sizeof(int));
            if (!tmp->fds_hash)
                EEXIT("failed to create five tuples hash");

            tmp->dport_listen_hash = create_hash("listen hash", SOCK_MAX_COUNT, sizeof(uint16_t));
            if (!tmp->fds_hash)
                EEXIT("failed to create five tuples hash");


            sock_table = tmp;
        }

        pthread_mutex_unlock(&mutex);
    }

    return sock_table;
}
