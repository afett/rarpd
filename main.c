/*
 * Copyright (c) 2012 Andreas Fett.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <linux/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <netpacket/packet.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>

#define XLOG_DEBUG(...) \
	syslog(LOG_DEBUG, __VA_ARGS__)
#define XLOG_INFO(...) \
	syslog(LOG_INFO, __VA_ARGS__)
#define XLOG_ERR(...) \
	syslog(LOG_ERR, __VA_ARGS__)
#define XLOG_WARNING(...) \
	syslog(LOG_WARNING, __VA_ARGS__)

struct link {
	size_t index;
	char name[IFNAMSIZ + 1];
	in_addr_t addr;
	int fd;
};

struct nl_ctx {
	int fd;
	struct sockaddr_nl sa;
};

struct rarpd {
	struct nl_ctx nl_ctx;
	size_t link_count;
	struct link *link;
	nfds_t nfds;
	struct pollfd *fds;
};

#define ARPHRD_ETHER	1
#define ETH_P_RARP      0x8035

struct nl_cb;

typedef void (*nl_link_cb)(int, unsigned short, unsigned int, const char *, void *);
typedef void (*nl_addr_cb)(int, in_addr_t, void *);
typedef void (*nl_msg_parse)(struct nlmsghdr *nlp, struct nl_cb *);

struct nl_cb {
	uint16_t msg_type;
	nl_msg_parse parse_msg;
	void *parse_cb;
	void *aux;
};

int nl_open(struct nl_ctx *nl_ctx)
{
	int ret;

	nl_ctx->fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
	if (nl_ctx->fd < 0)  {
		XLOG_ERR("error opening netlink socket: %s", strerror(errno));
		return -1;
	}

	memset(&nl_ctx->sa, 0, sizeof(struct sockaddr_nl));
	nl_ctx->sa.nl_family = AF_NETLINK;
	nl_ctx->sa.nl_pid = 0;
	nl_ctx->sa.nl_groups = 0;

	ret = bind(nl_ctx->fd, (struct sockaddr *) &nl_ctx->sa, sizeof(struct sockaddr_nl));
	if (ret < 0)  {
		XLOG_ERR("error binding netlink socket: %s", strerror(errno));
		return -1;
	}

	return 0;
}

void nl_close(struct nl_ctx *nl_ctx)
{
	if (nl_ctx->fd != -1) {
		close(nl_ctx->fd);
	}
}

bool nl_add_attr(struct nlmsghdr *nlm, unsigned short type, size_t len, void *data)
{
	size_t offs = NLMSG_ALIGN(nlm->nlmsg_len);
	struct rtattr *rta = (struct rtattr *) ((char*) nlm + offs);
	rta->rta_type = type;
	rta->rta_len = RTA_LENGTH(len);

	memcpy(RTA_DATA(rta), data, len);
	nlm->nlmsg_len = NLMSG_ALIGN(nlm->nlmsg_len) + RTA_LENGTH(len);
	return RTA_OK(rta, RTA_LENGTH(len));
}

size_t nl_create_msg(char *buf, size_t size, uint16_t type, uint16_t flags, int family)
{
	struct nlmsghdr *nlp;
	struct rtgenmsg *msgp;

	memset(buf, 0, size);
	nlp = (struct nlmsghdr *) buf;

	nlp->nlmsg_flags = flags;
	nlp->nlmsg_type = type;
	nlp->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	msgp = (struct rtgenmsg *) NLMSG_DATA(nlp);
	msgp->rtgen_family = family;

	return nlp->nlmsg_len;
}

int nl_list_links(struct nl_ctx *nl_ctx)
{
	int ret;
	size_t size;
	char buf[1024];

	size = nl_create_msg(buf, sizeof(buf), RTM_GETLINK, NLM_F_REQUEST|NLM_F_DUMP, PF_PACKET);
	ret = send(nl_ctx->fd, buf, size, 0);
	if (ret != size) {
		XLOG_ERR("error sending netlink message: %s", strerror(errno));
		return -1;
	}

	return 0;
}

void add_link(int ifindex, unsigned short iftype, unsigned int ifflags, const char *name, void *aux)
{
	struct rarpd *rarpd;
	struct link *link;

	if (iftype != ARPHRD_ETHER) {
		XLOG_INFO("skipping %s: no ethernet", name);
		return;
	}

	if (!(ifflags & IFF_RUNNING)) {
		XLOG_INFO("skipping %s: link is down", name);
		return;
	}

	XLOG_INFO("adding link %s", name);
	rarpd = (struct rarpd *) aux;
	++rarpd->link_count;
	rarpd->link = realloc(rarpd->link, rarpd->link_count * sizeof(struct link));
	link = &rarpd->link[rarpd->link_count - 1];
	link->index = ifindex;
	snprintf(link->name, sizeof(link->name), "%s", name);
	link->addr = 0;
}

void nl_parse_link_msg(struct nlmsghdr *nlp, struct nl_cb *cb)
{
	nl_link_cb link_cb;
	struct ifinfomsg *ifinfo;
	struct rtattr *rtap;
	char *name;
	size_t len;

	name = NULL;
	ifinfo = NLMSG_DATA(nlp);
	rtap = IFLA_RTA(ifinfo);
	len = IFLA_PAYLOAD(nlp);

	for (; RTA_OK(rtap, len) && !name; rtap = RTA_NEXT(rtap, len)) {
		switch (rtap->rta_type) {
		case IFLA_IFNAME:
			name = (char *)RTA_DATA(rtap);
			break;
		default:
			break;
		}
	}

	if (!name) {
		XLOG_ERR("could not get name for link %u", ifinfo->ifi_index);
		return;
	}

	link_cb = (nl_link_cb) cb->parse_cb;
	link_cb(ifinfo->ifi_index, ifinfo->ifi_type, ifinfo->ifi_flags, name, cb->aux);
}


void link_add_addr(int ifindex, in_addr_t addr, void *aux)
{
	int i;
	struct rarpd *rarpd;
	char addrstr[INET_ADDRSTRLEN];
	char used[INET_ADDRSTRLEN];

	rarpd = (struct rarpd *) aux;

	for (i = 0; i < rarpd->link_count; ++i) {
		if (rarpd->link[i].index != ifindex) {
			continue;
		}

		inet_ntop(AF_INET, &addr, addrstr, sizeof(addrstr));
		if (rarpd->link[i].addr != 0) {
			inet_ntop(AF_INET, &rarpd->link[i].addr, used, sizeof(used));
			XLOG_WARNING("ignoring address %s for link %s using %s",
				addrstr, rarpd->link[i].name, used);
			continue;
		}

		XLOG_INFO("using address %s for link %s", addrstr, rarpd->link[i].name);
		rarpd->link[i].addr = addr;
	}
}

void nl_parse_addr_msg(struct nlmsghdr *nlp, struct nl_cb *cb)
{
	struct ifaddrmsg *ifaddr;
	struct rtattr *rtap;
	nl_addr_cb addr_cb;
	size_t len;
	in_addr_t *addr;

	addr = NULL;
	ifaddr = NLMSG_DATA(nlp);
	rtap = IFLA_RTA(ifaddr);
	len = IFLA_PAYLOAD(nlp);

	for (; RTA_OK(rtap, len); rtap = RTA_NEXT(rtap, len)) {
		switch (rtap->rta_type) {
		case IFA_LOCAL:
			addr = (in_addr_t*)RTA_DATA(rtap);
			break;
		default:
			break;
		}
	}

	if (!addr) {
		XLOG_ERR("could not get addr for link %u", ifaddr->ifa_index);
		return;
	}

	addr_cb = (nl_addr_cb) cb->parse_cb;
	addr_cb(ifaddr->ifa_index, *addr, cb->aux);
}

bool nl_parse(char *buf, ssize_t len, struct nl_cb *cb)
{
	struct nlmsghdr *nlp;
	struct rtmsg *rtp;
	struct nlmsgerr *err;

	nlp = (struct nlmsghdr *) buf;
	for(;NLMSG_OK(nlp, len);nlp=NLMSG_NEXT(nlp, len)) {
		rtp = (struct rtmsg *) NLMSG_DATA(nlp);
		switch (nlp->nlmsg_type) {
		case NLMSG_ERROR:
			err = (struct nlmsgerr *) NLMSG_DATA(nlp);
			XLOG_ERR("received netlink error %s", strerror(-err->error));
		case NLMSG_DONE:
			return false;
		default:
			if (nlp->nlmsg_type == cb->msg_type) {
				cb->parse_msg(nlp, cb);
				break;
			}
			XLOG_DEBUG("unhandled netlink message of type %u", nlp->nlmsg_type);
			break;
		}
		if (!(nlp->nlmsg_flags & NLM_F_MULTI)) {
			return false;
		}
	}
	return true;
}

int nl_receive(struct nl_ctx *nl_ctx, struct nl_cb *cb)
{
	char buf[32768];
	ssize_t len;

	do {
		memset(buf, 0, sizeof(buf));
		len = recv(nl_ctx->fd, buf, sizeof(buf), 0);
		if (len < 0) {
			XLOG_ERR("error receiving netlink message: %s", strerror(errno));
			return -1;
		}
	} while (nl_parse(buf, len, cb));

	return 0;
}

int nl_get_v4addr(struct nl_ctx *nl_ctx)
{
	int ret;
	size_t size;
	char buf[1024];

	size = nl_create_msg(buf, sizeof(buf), RTM_GETADDR, NLM_F_REQUEST|NLM_F_DUMP, PF_INET);

	ret = send(nl_ctx->fd, buf, size, 0);
	if (ret != size) {
		XLOG_ERR("error sending netlink message: %s", strerror(errno));
		return -1;
	}

	return 0;
}

int get_addresses(struct rarpd *rarpd)
{
	struct nl_cb addr_cb;

	addr_cb.msg_type = RTM_NEWADDR;
	addr_cb.parse_msg = nl_parse_addr_msg;
	addr_cb.parse_cb = link_add_addr;
	addr_cb.aux = rarpd;

	if (nl_get_v4addr(&rarpd->nl_ctx) != 0) {
		return -1;
	}

	return nl_receive(&rarpd->nl_ctx, &addr_cb);
}

void filter_links(struct rarpd *rarpd)
{
	int i;

	i = 0;
	while (i < rarpd->link_count) {
		if (rarpd->link[i].addr != 0) {
			++i;
			continue;
		}

		--rarpd->link_count;
		if (rarpd->link_count != i) {
			memcpy(&rarpd->link[i],
				&rarpd->link[rarpd->link_count],
				sizeof(struct link));
		}
	}

	if (rarpd->link_count != 0) {
		rarpd->link = realloc(rarpd->link,
			rarpd->link_count * sizeof(struct link));
	} else {
		free(rarpd->link);
		rarpd->link = NULL;
	}
}

int get_links(struct rarpd *rarpd)
{
	struct nl_cb link_cb;

	link_cb.msg_type = RTM_NEWLINK;
	link_cb.parse_msg = nl_parse_link_msg;
	link_cb.parse_cb = add_link;
	link_cb.aux = rarpd;

	if (nl_list_links(&rarpd->nl_ctx) != 0) {
		return -1;
	}

	return nl_receive(&rarpd->nl_ctx, &link_cb);
}

int set_promisc(int fd, size_t ifindex)
{
	int ret;
	struct packet_mreq mreq;

	memset(&mreq, 0, sizeof(struct packet_mreq));
	mreq.mr_ifindex = ifindex;
	mreq.mr_type = PACKET_MR_PROMISC;

	ret = setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP,
		&mreq, sizeof(struct packet_mreq));

	if (ret != 0) {
		XLOG_ERR("error setting promisc mode on link %u: %s",
			ifindex, strerror(errno));
		return -1;
	}

	return 0;
}

int do_bind(int fd, size_t ifindex)
{
	int ret;
	struct sockaddr_ll addr;

	memset(&addr, 0, sizeof(struct sockaddr_ll));
	addr.sll_family = PF_PACKET;
	addr.sll_ifindex = ifindex;
	ret = bind(fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_ll));
	if (ret == -1) {
		XLOG_ERR("error binding socket on %u: %s",
			ifindex, strerror(errno));
		return -1;
	}

	return 0;
}

void rarpd_add_pollfd(struct rarpd *rarpd, int fd)
{
	rarpd->fds[rarpd->nfds].fd = fd;
	rarpd->fds[rarpd->nfds].events = POLLIN;
	rarpd->fds[rarpd->nfds].revents = 0;
	++rarpd->nfds;
}

int open_socket()
{
	int fd;

	fd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_RARP));
	if (fd < 0) {
		XLOG_ERR("error opening socket %s", strerror(errno));
		return -1;
	}

	if (fcntl(fd, F_SETFL, O_NONBLOCK) != 0) {
		XLOG_ERR("error setting socket nonblocking %s", strerror(errno));
		close(fd);
		return -1;
	}

	return fd;
}

int setup_links(struct rarpd *rarpd)
{
	int i, fd;

	rarpd->fds = malloc(rarpd->link_count * sizeof(struct pollfd));

	for (i = 0; i < rarpd->link_count; ++i) {
		fd = open_socket();
		if (fd < 0) {
			goto err;
		}

		if (do_bind(fd, rarpd->link[i].index) != 0) {
			goto err;
		}

		if (set_promisc(fd, rarpd->link[i].index) != 0) {
			goto err;
		}

		rarpd->link[i].fd = fd;
		rarpd_add_pollfd(rarpd, fd);
	}

	return 0;
err:
	close(fd);
	XLOG_ERR("error setting up %s", rarpd->link[i].name);
	return -1;
}

struct link* find_link_by_fd(int fd, struct link* link, size_t size)
{
	int i;
	for (i = 0; i < size; ++i) {
		if (link[i].fd == fd) {
			return &link[i];
		}
	}

	return NULL;
}

void dump_packet(char *buf, size_t size)
{
	int i;

	for (i = 0; i < size; ++i) {
		fprintf(stderr, "%02x ", (unsigned char) buf[i]);
		if (((i+1) % 16) == 0) {
			fprintf(stderr, "%s", "\n");
		}
	}
}

void dispatch_requests(struct rarpd *rarpd, int events)
{
	int i;
	int ret;
	int processed;
	struct link *link;
	char buf[1500];

	processed = 0;
	for (i = 0; i < rarpd->nfds; ++i) {
		if (rarpd->fds[i].revents == 0) {
			continue;
		}

		link = find_link_by_fd(rarpd->fds[i].fd, rarpd->link, rarpd->link_count);
		if (link == NULL) {
			XLOG_ERR("received poll event for unkown link");
			return;
		}

		XLOG_ERR("received poll event for %s", link->name);
		memset(buf, 0, sizeof(buf));
		ret = read(link->fd, buf, sizeof(buf));
		if (ret < 0) {
			XLOG_ERR("read error on %s: %s", link->name, strerror(errno));
		}

		XLOG_DEBUG("read %i octets", ret);
		dump_packet(buf, ret);

		if (++processed == events) {
			return;
		}
	}
}

void handle_requests(struct rarpd *rarpd)
{
	int events;

	for(;;) {
		events = poll(rarpd->fds, rarpd->nfds, -1);
		if (events < 0) {
			XLOG_ERR("poll error: %s", strerror(errno));
			return;
		}

		dispatch_requests(rarpd, events);
	}
}

int main(int argc, char *argv[])
{
	struct rarpd rarpd;

	rarpd.link_count = 0;
	rarpd.link = NULL;
	rarpd.nfds = 0;
	rarpd.fds = NULL;
	rarpd.nl_ctx.fd = -1;

	openlog("rarpd", LOG_PERROR|LOG_PID, LOG_DAEMON);
	if (nl_open(&rarpd.nl_ctx) != 0) {
		return EXIT_FAILURE;
	}

	if (get_links(&rarpd) != 0) {
		return EXIT_FAILURE;
	}

	if (get_addresses(&rarpd) != 0) {
		return EXIT_FAILURE;
	}

	nl_close(&rarpd.nl_ctx);

	filter_links(&rarpd);
	if (rarpd.link_count == 0) {
		XLOG_ERR("no usable links found");
		return EXIT_FAILURE;
	}

	if (setup_links(&rarpd) != 0) {
		return EXIT_FAILURE;
	}

	handle_requests(&rarpd);

	free(rarpd.fds);
	free(rarpd.link);

	return 0;
}
