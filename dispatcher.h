#ifndef RARPD_DISPATCHER_H
#define RARPD_DISPATCHER_H

#include <poll.h>

enum dispatch_action {
	DISPATCH_CONTINUE = 0,
	DISPATCH_ABORT
};

typedef enum dispatch_action (io_handler)(int , short, void *);

struct dispatcher {
	nfds_t nfds;
	struct pollfd *fds;
	struct poll_handler *handler;
};

struct fd_handler {
	struct dispatcher *dispatcher;
	int index;
};

void dispatcher_init(struct dispatcher *dispatcher);
struct fd_handler dispatcher_watch(struct dispatcher *dispatcher, int fd,
	io_handler *handler, void *aux);
void dispatcher_flags(struct fd_handler *handler, short flags);
int dispatcher_run(struct dispatcher *dispatcher);
void dispatcher_cleanup(struct dispatcher *dispatcher);

#endif
