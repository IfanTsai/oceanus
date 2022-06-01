#include "fd.h"

__fd_set_t *get_fd_set_instance(void)
{
    static __fd_set_t __fd_set = {
        .fds_bits = { 0 },
        .rwlock = PTHREAD_RWLOCK_INITIALIZER,
    };


    return &__fd_set;
}

