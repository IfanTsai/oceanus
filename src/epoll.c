#include "epoll.h"
#include "fd.h"
#include "sock.h"
#include <rte_malloc.h>
#include <sys/param.h>

#define get_unused_fd() __get_unused_fd(get_fd_set_instance())
#define put_unused_fd(fd) __put_unused_fd(get_fd_set_instance(), fd)

static epitem_t *ep_find(eventpoll_t *ep, int fd)
{
    rb_node_t *rbp = ep->rbr.rb_node;

    while (rbp) {
        epitem_t *epi = rb_entry(rbp, epitem_t, rbn);
        if (fd > epi->fd)
            rbp = rbp->rb_right;
        else if (fd < epi->fd)
            rbp = rbp->rb_left;
        else
            return epi;
    }

    return NULL;
}

static void ep_insert(eventpoll_t *ep, epitem_t *epi)
{
    rb_node_t **p = &ep->rbr.rb_node, *parent = NULL;

    while (*p) {
        parent = *p;
        epitem_t *epic = rb_entry(parent, epitem_t, rbn);
        p = epi->fd > epic->fd ? &parent->rb_right : &parent->rb_left;
    }

    rb_link_node(&epi->rbn, parent, p);
    rb_insert_color(&epi->rbn, &ep->rbr);
}

static inline void ep_remove(eventpoll_t *ep, epitem_t *epi)
{
    rb_erase(&epi->rbn, &ep->rbr);
}

int o_epoll_create(int size)
{
    if (size <= 0) {
        errno = EINVAL;
        return -1;
    }

    int epfd = get_unused_fd();

    eventpoll_t *ep = rte_malloc(NULL, sizeof(eventpoll_t), 0);
    ep->fd = epfd;

    LIST_INIT(&ep->rdlist);
    ep->rbr = RB_ROOT;

    if (pthread_mutex_init(&ep->mutex, NULL))
        goto err_init_mutex;

    if (pthread_cond_init(&ep->cond, NULL))
        goto err_init_cond;

    if (pthread_spin_init(&ep->lock, PTHREAD_PROCESS_SHARED))
        goto err_init_spin;

    add_eventpoll_to_fds_hash(ep);

    return ep->fd;

err_init_spin:
    pthread_cond_destroy(&ep->cond);
err_init_cond:
    pthread_mutex_destroy(&ep->mutex);
err_init_mutex:
    rte_free(ep);

    return -1;
}

int o_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
{
    if (!event && op != EPOLL_CTL_DEL)  {
        errno = EINVAL;
        return -1;
    }

    eventpoll_t *ep = get_eventpoll_from_fd(epfd);
    if (!ep) {
        errno = EBADF;
        return -1;
    }

    if (EPOLL_CTL_ADD == op) {
        pthread_mutex_lock(&ep->mutex);

        epitem_t *epi = ep_find(ep, fd);
        if (epi) {               // have inserted
            errno = EINVAL;
            goto out_mutex_unlock;
        }

        epi = rte_malloc(NULL, sizeof(epitem_t), 0);
        if (!epi) {
            errno = ENOMEM;
            goto out_mutex_unlock;
        }

        epi->fd = fd;
        memcpy(&epi->event, event, sizeof(epoll_event_t));
        ep_insert(ep, epi);

        pthread_mutex_unlock(&ep->mutex);
    } else if (EPOLL_CTL_DEL == op) {
        pthread_mutex_lock(&ep->mutex);

        epitem_t *epi = ep_find(ep, fd);
        if (!epi) {
            errno = EINVAL;
            goto out_mutex_unlock;
        }

        ep_remove(ep, epi);
        rte_free(epi);

        pthread_mutex_unlock(&ep->mutex);
    } else if (EPOLL_CTL_MOD == op) {
        epitem_t *epi = ep_find(ep, fd);
        if (!epi) {
            errno = EINVAL;
            goto out_mutex_unlock;
        }

        epi->event.events = event->events;
    }

    return 0;

out_mutex_unlock:
    pthread_mutex_unlock(&ep->mutex);

    return -1;
}

int o_epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout)
{
    if (!events || maxevents <= 0) {
        errno = EINVAL;
        return -1;
    }

    eventpoll_t *ep = get_eventpoll_from_fd(epfd);
    if (!ep) {
        errno = EBADF;
        return -1;
    }

    pthread_mutex_lock(&ep->mutex);

    while (ep->rd_num == 0 && timeout != 0) {
        if (timeout > 0) {
            struct timespec deadline;
            clock_gettime(CLOCK_REALTIME, &deadline);

            if (timeout >= 1000) {
                int sec = timeout / 1000;
                deadline.tv_sec += sec;
                timeout -= sec * 1000;
            }

            deadline.tv_nsec += timeout * 1000000;

            if (deadline.tv_nsec >= 1000000000) {
                deadline.tv_sec++;
                deadline.tv_nsec -= 1000000000;
            }

            int ret = pthread_cond_timedwait(&ep->cond, &ep->mutex, &deadline);
            if (ret && ret != ETIMEDOUT)
                goto out_mutex_unlock;

            timeout = 0;
        } else if (timeout < 0)
            pthread_cond_wait(&ep->cond, &ep->mutex);
    }

    pthread_mutex_unlock(&ep->mutex);

    pthread_spin_lock(&ep->lock);

    int cnt;
    int num = MIN(ep->rd_num, maxevents);
    for (cnt = 0; cnt < num && !LIST_EMPTY(&ep->rdlist); cnt++) {
        epitem_t *epi = LIST_FIRST(&ep->rdlist);
        epi->rdy = false;
        memcpy(&events[cnt], &epi->event, sizeof(epoll_event_t));

        LIST_REMOVE(epi, rdlink);
        ep->rd_num--;
    }

    pthread_spin_unlock(&ep->lock);

    return cnt;

out_mutex_unlock:
    pthread_mutex_unlock(&ep->mutex);

    return -1;
}

int epoll_event_cb(eventpoll_t *ep, int fd, uint32_t event)
{
    if (!ep)
        return -1;

    epitem_t *epi = ep_find(ep, fd);
    if (!epi)
        return -1;

    // only update event if epi is in ready list
    if (epi->rdy) {
        epi->event.events |= event;

        return 0;
    }

    pthread_spin_lock(&ep->lock);

    epi->rdy = true;
    epi->event.events = event;
    LIST_INSERT_HEAD(&ep->rdlist, epi, rdlink);
    ep->rd_num++;

    pthread_spin_unlock(&ep->lock);

    pthread_mutex_lock(&ep->mutex);
    pthread_cond_signal(&ep->cond);
    pthread_mutex_unlock(&ep->mutex);

    return 0;
}
