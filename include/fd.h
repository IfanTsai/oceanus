#ifndef __FD_H__
#define __FD_H__

#include <pthread.h>

#define ___FD_SETSIZE	65536
#define __NFDBITS	(8 * sizeof(unsigned long))
#define __FDSET_LONGS	(___FD_SETSIZE / __NFDBITS)

typedef struct {
    unsigned long fds_bits[__FDSET_LONGS];
    pthread_rwlock_t rwlock;
} __fd_set_t;

static inline void __FD_SET(unsigned long fd, __fd_set_t *fdsetp)
{
    unsigned long tmp = fd / __NFDBITS;
    unsigned long rem = fd % __NFDBITS;

    pthread_rwlock_wrlock(&fdsetp->rwlock);
    fdsetp->fds_bits[tmp] |= (1UL << rem);
    pthread_rwlock_unlock(&fdsetp->rwlock);
}

static inline void __FD_CLR(unsigned long fd, __fd_set_t *fdsetp)
{
    unsigned long tmp = fd / __NFDBITS;
    unsigned long rem = fd % __NFDBITS;

    pthread_rwlock_wrlock(&fdsetp->rwlock);
    fdsetp->fds_bits[tmp] &= ~(1UL << rem);
    pthread_rwlock_unlock(&fdsetp->rwlock);
}

static inline int __FD_ISSET(unsigned long fd, __fd_set_t *fdsetp)
{
    unsigned long tmp = fd / __NFDBITS;
    unsigned long rem = fd % __NFDBITS;

    pthread_rwlock_rdlock(&fdsetp->rwlock);
    int is_set = (fdsetp->fds_bits[tmp] & (1UL << rem)) != 0;
    pthread_rwlock_unlock(&fdsetp->rwlock);

    return is_set;
}

static inline void __FD_ZERO(__fd_set_t *fdsetp)
{
    pthread_rwlock_wrlock(&fdsetp->rwlock);
    for (int i = __FDSET_LONGS; i; i--)
        fdsetp->fds_bits[i] = 0;
    pthread_rwlock_unlock(&fdsetp->rwlock);
}

static inline int __get_unused_fd(__fd_set_t *fdsetp)
{
    // 0, 1, 2 default for stdin, stdout, stderr
    for (int fd = 3; fd < ___FD_SETSIZE; fd++) {
        if (!__FD_ISSET(fd, fdsetp)) {
            __FD_SET(fd, fdsetp);

            return fd;
        }
    }

    return -1;
}

static inline void __put_unused_fd(__fd_set_t *fdsetp, int fd)
{
    __FD_CLR(fd, fdsetp);
}


#endif
