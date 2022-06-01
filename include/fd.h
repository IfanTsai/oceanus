#ifndef __FD_H__
#define __FD_H__

#include <pthread.h>

#define _FD_SETSIZE	65536
#define _NFDBITS	(8 * sizeof(unsigned long))
#define _FDSET_LONGS	(__FD_SETSIZE / _NFDBITS)

typedef struct {
    unsigned long fds_bits[_FDSET_LONGS];
    pthread_rwlock_t rwlock;
} __fd_set_t;

static inline void _FD_SET(unsigned long fd, __fd_set_t *fdsetp)
{
    unsigned long tmp = fd / _NFDBITS;
    unsigned long rem = fd % _NFDBITS;

    pthread_rwlock_wrlock(&fdsetp->rwlock);
    fdsetp->fds_bits[tmp] |= (1UL << rem);
    pthread_rwlock_unlock(&fdsetp->rwlock);
}

static inline void _FD_CLR(unsigned long fd, __fd_set_t *fdsetp)
{
    unsigned long tmp = fd / _NFDBITS;
    unsigned long rem = fd % _NFDBITS;

    pthread_rwlock_wrlock(&fdsetp->rwlock);
    fdsetp->fds_bits[tmp] &= ~(1UL << rem);
    pthread_rwlock_unlock(&fdsetp->rwlock);
}

static inline int _FD_ISSET(unsigned long fd, __fd_set_t *fdsetp)
{
    unsigned long tmp = fd / _NFDBITS;
    unsigned long rem = fd % _NFDBITS;

    pthread_rwlock_rdlock(&fdsetp->rwlock);
    int is_set = (fdsetp->fds_bits[tmp] & (1UL << rem)) != 0;
    pthread_rwlock_unlock(&fdsetp->rwlock);

    return is_set;
}

static inline void _FD_ZERO(__fd_set_t *fdsetp)
{
    pthread_rwlock_wrlock(&fdsetp->rwlock);
    for (int i = _FDSET_LONGS; i; i--)
        fdsetp->fds_bits[i] = 0;
    pthread_rwlock_unlock(&fdsetp->rwlock);
}

static inline int __get_unused_fd(__fd_set_t *fdsetp)
{
    // 0, 1, 2 default for stdin, stdout, stderr
    for (int fd = 3; fd < _FD_SETSIZE; fd++) {
        if (!_FD_ISSET(fd, fdsetp)) {
            _FD_SET(fd, fdsetp);

            return fd;
        }
    }

    return -1;
}

static inline void __put_unused_fd(__fd_set_t *fdsetp, int fd)
{
    _FD_CLR(fd, fdsetp);
}

__fd_set_t *get_fd_set_instance(void);

#endif
