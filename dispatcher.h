#ifndef RARPD_DISPATCHER_H
#define RARPD_DISPATCHER_H

#include <poll.h>

enum dispatch_action {
	DISPATCH_CONTINUE = 0,
	DISPATCH_ABORT
};

typedef enum dispatch_action (io_handler)(int , short, void *);

struct poll_handler {
	short events;
	io_handler *handler;
	void *aux;
};

struct dispatcher {
	nfds_t nfds;
	struct pollfd *fds;
	struct poll_handler *handler;
};

void dispatcher_init(struct dispatcher *dispatcher);
struct poll_handler* dispatcher_watch(struct dispatcher *dispatcher, int fd,
	io_handler *handler, void *aux);
int dispatcher_run(struct dispatcher *dispatcher);
void dispatcher_cleanup(struct dispatcher *dispatcher);

#endif
