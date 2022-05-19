#include "arp_table.h"

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

arp_table_t *get_arp_table_instance(void)
{
    static arp_table_t *arp_table = NULL;

    if (!arp_table) {
        pthread_mutex_lock(&mutex);

        if (!arp_table) {
            arp_table_t *tmp = (arp_table_t *)rte_malloc(NULL, sizeof(arp_table_t), 0);
            if (!tmp)
                EEXIT("failed to malloc arp table");

            tmp->hash = create_hash("arp table", ARP_TABLE_ENTRIES, sizeof(uint32_t));
            if (!tmp->hash)
                EEXIT("failed to create arp hash table");

            arp_table = tmp;
        }

        pthread_mutex_unlock(&mutex);
    }

    return arp_table;
}
