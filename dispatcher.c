#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include "xlog.h"
#include "dispatcher.h"

void dispatcher_init(struct dispatcher *dispatcher)
{
	memset(dispatcher, 0, sizeof(struct dispatcher));
}

void dispatcher_cleanup(struct dispatcher *dispatcher)
{
	free(dispatcher->handler);
	free(dispatcher->fds);
	memset(dispatcher, 0, sizeof(struct dispatcher));
}

struct poll_handler*
dispatcher_watch(struct dispatcher *dispatcher, int fd,
	io_handler *io_handler, void *aux)
{
	struct poll_handler *handler;
	struct pollfd *pollfd;

	++dispatcher->nfds;
	dispatcher->handler = realloc(dispatcher->handler,
		dispatcher->nfds * sizeof(struct poll_handler));

	dispatcher->fds = realloc(dispatcher->fds,
		dispatcher->nfds * sizeof(struct pollfd));

	if (dispatcher->handler == NULL || dispatcher->fds == NULL) {
		exit(EXIT_FAILURE);
	}

	pollfd = &dispatcher->fds[dispatcher->nfds - 1];
	pollfd->events = 0;
	pollfd->revents = 0;
	pollfd->fd = fd;

	handler = &dispatcher->handler[dispatcher->nfds - 1];
	handler->handler = io_handler;
	handler->aux = aux;
	return handler;
}

typedef enum dispatch_action (foreach_fn)(struct poll_handler *, struct pollfd *);

static enum dispatch_action
foreach_handler(struct dispatcher *dispatcher, foreach_fn *fn)
{
	struct pollfd *pollfd;
	struct poll_handler *handler;
	enum dispatch_action action;
	nfds_t i;

	action = DISPATCH_CONTINUE;
	pollfd = dispatcher->fds;
	handler = dispatcher->handler;
	for (i = 0; i < dispatcher->nfds; ++i, ++pollfd, ++handler) {
		action = fn(handler, pollfd);
		if (action == DISPATCH_ABORT) {
			break;
		}
	}

	return action;
}

static enum dispatch_action
dispatch(struct poll_handler *handler, struct pollfd *pollfd)
{
	if (pollfd->revents == 0) {
		return DISPATCH_CONTINUE;
	}

	if (pollfd->revents & POLLERR) {
		XLOG_ERR("poll error on fd %i", pollfd->fd);
		return DISPATCH_ABORT;
	}

	return handler->handler(pollfd->fd, pollfd->events, handler->aux);
}

static enum dispatch_action
set_events(struct poll_handler *handler, struct pollfd *pollfd)
{
	pollfd->events = handler->events;
	pollfd->revents = 0;
	return DISPATCH_CONTINUE;
}

int dispatcher_run(struct dispatcher *dispatcher)
{
	int ret;

	for(;;) {
		foreach_handler(dispatcher, set_events);

		do {
			ret = poll(dispatcher->fds, dispatcher->nfds, -1);
		} while (ret < 0 && errno == EINTR);

		if (ret < 0) {
			XLOG_ERR("poll error: %s", strerror(errno));
			return -1;
		}

		if (foreach_handler(dispatcher, dispatch) == DISPATCH_ABORT) {
			return 0;
		}
	}
}
