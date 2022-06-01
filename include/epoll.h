#ifndef __EPOLL_H__
#define __EPOLL_H__

#include "rbtree.h"
#include "config.h"
#include <pthread.h>
#include <stdint.h>
#include <sys/queue.h>
#include <stdbool.h>

#define EPOLL_CTL_ADD 1
#define EPOLL_CTL_DEL 2
#define EPOLL_CTL_MOD 3

enum EPOLL_EVENTS
{
	EPOLLNONE = 0x0000,
	EPOLLIN   = 0x0001,
	EPOLLPRI  = 0x0002,
	EPOLLOUT  = 0x0004,
	EPOLLRDNORM = 0x0040,
	EPOLLRDBAND = 0x0080,
	EPOLLWRNORM = 0x0100,
	EPOLLWRBAND = 0x0200,
	EPOLLMSG = 0x0400,
	EPOLLERR = 0x0008,
	EPOLLHUP = 0x0010,
	EPOLLRDHUP = 0x2000,
	EPOLLONESHOT = (1 << 30),
	EPOLLET = (1 << 31)
};

typedef union epoll_data {
    void *ptr;
    int fd;
    uint32_t u32;
    uint64_t u64;
} epoll_data_t;

typedef struct epoll_event {
    uint32_t events;
    epoll_data_t data;
} epoll_event_t;

typedef struct epitem {
    /* RB tree node used to link this structure to the eventpoll RB tree */
    rb_node_t rbn;
    /* List header used to link this structure to the eventpoll ready list */
    LIST_ENTRY(epitem) rdlink;
    /* The structure that describe the interested events and the source fd */
    epoll_event_t event;

    bool rdy;
    int fd;
} epitem_t;

typedef struct {
    /* RB tree root used to store monitored fd structs */
    rb_root_t rbr;
    /* List of ready file descriptors */
    LIST_HEAD(, epitem) rdlist;

    pthread_spinlock_t lock;
    pthread_mutex_t mutex;
    pthread_cond_t cond;

    int fd;
    int rd_num;
} eventpoll_t;

int o_epoll_create(int size);
int o_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);
int o_epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout);
int epoll_event_cb(eventpoll_t *ep, int fd, uint32_t event); // only call by protocol stack

#endif
