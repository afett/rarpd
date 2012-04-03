#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

#include "xlog.h"
#include "sighandler.h"

static int signal_fd = -1;

static void sig_handler(int signo)
{
	write(signal_fd, &signo, sizeof(int));
}

static int create_pipe(int fds[])
{
	int ret;
	ret = pipe(fds);
	if (ret != 0) {
		XLOG_ERR("pipe() failed: %s", strerror(errno));
		return -1;
	}

	ret |= fcntl(fds[0], F_SETFL, O_NONBLOCK);
	ret |= fcntl(fds[1], F_SETFL, O_NONBLOCK);
	if (ret != 0) {
		XLOG_ERR("error setting fd nonblocking %s",
			strerror(errno));
		goto err;
	}

	ret |= fcntl(fds[0], F_SETFD, FD_CLOEXEC);
	ret |= fcntl(fds[1], F_SETFD, FD_CLOEXEC);
	if (ret != 0) {
		XLOG_ERR("error setting fd cloexec flag %s",
			strerror(errno));
		goto err;
	}

	return 0;
err:
	close(fds[0]);
	close(fds[1]);
	return -1;
}

int install_signal_fd()
{
	int ret;
	int fds[2];
	struct sigaction sigact;

	ret = create_pipe(fds);
	if (ret != 0) {
		return -1;
	}

	signal_fd = fds[1];
	memset(&sigact,0,sizeof(struct sigaction));
	sigemptyset(&sigact.sa_mask);
        sigact.sa_handler = sig_handler;
	sigact.sa_flags = SA_RESTART;

        ret |= sigaction(SIGTERM, &sigact, NULL);
        ret |= sigaction(SIGQUIT, &sigact, NULL);
        ret |= sigaction(SIGUSR1, &sigact, NULL);
        ret |= sigaction(SIGUSR2, &sigact, NULL);
        ret |= sigaction(SIGINT, &sigact, NULL);

	if (ret != 0) {
		XLOG_ERR("sigaction() failed: %s", strerror(errno));
		close(fds[0]);
		close(fds[1]);
		return -1;
	}

	return fds[0];
}
