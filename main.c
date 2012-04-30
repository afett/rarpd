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
#include <dirent.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <fcntl.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netdb.h>
#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netpacket/packet.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "xlog.h"
#include "netlink.h"
#include "sighandler.h"

struct link {
	int ifindex;
	char name[IF_NAMESIZE + 1];
	in_addr_t in_addr;
	struct ether_addr ether_addr;
	struct pollfd* pollfd;
	struct sockaddr_ll src;
	char buf[1500];
};

enum {
	LISTEN_ALL = 1 << 0,
	DEBUG_MODE = 1 << 1,
	FOREGROUND = 1 << 2,
	LOG_REQ    = 1 << 3,
	BOOT_FILE  = 1 << 4,
};

struct rarpd {
	struct nl_ctx nl_ctx;
	size_t link_count;
	struct link *link;
	nfds_t nfds;
	struct pollfd *fds;
	unsigned int opts;
	char **ifname;
};

bool in_argv(const char *name, char **ifname)
{
	for (; *ifname != NULL; ++ifname) {
		if (strcmp(name, *ifname) == 0) {
			return true;
		}
	}
	return false;
}

void add_link(int ifindex, unsigned short iftype, unsigned int ifflags,
	const struct ether_addr *addr, const char *name, void *aux)
{
	struct rarpd *rarpd;
	struct link *link;

	rarpd = (struct rarpd *) aux;
	if (!(rarpd->opts & LISTEN_ALL) && !in_argv(name, rarpd->ifname)) {
		XLOG_INFO("skipping %s: not found in arguments", name);
		return;
	}

	if (iftype != ARPHRD_ETHER) {
		XLOG_INFO("skipping %s: no ethernet", name);
		return;
	}

	if (!(ifflags & IFF_RUNNING)) {
		XLOG_INFO("skipping %s: link is down", name);
		return;
	}

	XLOG_INFO("adding link %s: %s", name, ether_ntoa(addr));
	++rarpd->link_count;
	rarpd->link = realloc(rarpd->link,
		rarpd->link_count * sizeof(struct link));
	link = &rarpd->link[rarpd->link_count - 1];
	link->ifindex = ifindex;
	snprintf(link->name, sizeof(link->name), "%s", name);
	memcpy(&link->ether_addr, addr, sizeof(struct ether_addr));
	link->in_addr = 0;
}

void link_add_addr(int ifindex, in_addr_t addr, void *aux)
{
	size_t i;
	struct rarpd *rarpd;
	char addrstr[INET_ADDRSTRLEN];
	char used[INET_ADDRSTRLEN];

	rarpd = (struct rarpd *) aux;

	for (i = 0; i < rarpd->link_count; ++i) {
		if (rarpd->link[i].ifindex != ifindex) {
			continue;
		}

		inet_ntop(AF_INET, &addr, addrstr, sizeof(addrstr));
		if (rarpd->link[i].in_addr != 0) {
			inet_ntop(AF_INET, &rarpd->link[i].in_addr,
				used, sizeof(used));
			XLOG_WARNING("ignoring address %s for link %s using %s",
				addrstr, rarpd->link[i].name, used);
			continue;
		}

		XLOG_INFO("using address %s for link %s",
			addrstr, rarpd->link[i].name);
		rarpd->link[i].in_addr = addr;
	}
}

int get_addresses(struct rarpd *rarpd)
{
	struct nl_cb cb;

	if (nl_list_addr(&rarpd->nl_ctx) != 0) {
		return -1;
	}

	nl_init_addr_cb(&cb, link_add_addr, rarpd);
	return nl_receive(&rarpd->nl_ctx, &cb);
}

void filter_links(struct rarpd *rarpd)
{
	size_t i;

	i = 0;
	while (i < rarpd->link_count) {
		if (rarpd->link[i].in_addr != 0) {
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
	struct nl_cb cb;

	if (nl_list_links(&rarpd->nl_ctx) != 0) {
		return -1;
	}

	nl_init_link_cb(&cb, add_link, rarpd);
	return nl_receive(&rarpd->nl_ctx, &cb);
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

struct pollfd *rarpd_add_pollfd(struct rarpd *rarpd, int fd)
{
	struct pollfd* pollfd;

	pollfd = &rarpd->fds[rarpd->nfds];
	pollfd->fd = fd;
	pollfd->events = POLLIN;
	pollfd->revents = 0;
	++rarpd->nfds;
	return pollfd;
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
		XLOG_ERR("error setting socket nonblocking %s",
			strerror(errno));
		close(fd);
		return -1;
	}

	return fd;
}

int setup_links(struct rarpd *rarpd)
{
	size_t i;
	int fd;

	rarpd->fds = malloc(rarpd->link_count * sizeof(struct pollfd));

	for (i = 0; i < rarpd->link_count; ++i) {
		fd = open_socket();
		if (fd < 0) {
			goto err;
		}

		if (do_bind(fd, rarpd->link[i].ifindex) != 0) {
			goto err;
		}

		if (set_promisc(fd, rarpd->link[i].ifindex) != 0) {
			goto err;
		}

		rarpd->link[i].pollfd = rarpd_add_pollfd(rarpd, fd);
	}

	return 0;
err:
	close(fd);
	XLOG_ERR("error setting up %s", rarpd->link[i].name);
	return -1;
}

struct link* find_link_by_fd(int fd, struct link* link, size_t size)
{
	size_t i;
	for (i = 0; i < size; ++i, ++link) {
		if (link->pollfd->fd == fd) {
			return link;
		}
	}

	return NULL;
}

void dump_packet(char *buf, size_t size)
{
	size_t i;

	for (i = 0; i < size; ++i) {
		fprintf(stderr, "%02x ", (unsigned char) buf[i]);
		if (((i+1) % 16) == 0) {
			fprintf(stderr, "%s", "\n");
		}
	}
}

bool check_frame(struct sockaddr_ll *addr, struct link *link)
{
	if (ntohs(addr->sll_protocol) != ETH_P_RARP) {
		XLOG_INFO(
			"frame check failed: no RARP packet: sll_protocol=0x%x",
			ntohs(addr->sll_protocol));
		return false;
	}

	if (addr->sll_ifindex != link->ifindex) {
		XLOG_INFO("frame check failed: wrong interface");
		return false;
	}

	if (addr->sll_hatype != ARPHRD_ETHER) {
		XLOG_INFO("frame check failed: no ethernet");
		return false;
	}

	if (addr->sll_pkttype != PACKET_BROADCAST) {
		XLOG_INFO("frame check failed: no broadcast");
		return false;
	}

	if (addr->sll_halen != sizeof(struct ether_addr)) {
		XLOG_INFO("frame check failed: bad source address length");
		return false;
	}

	return true;
}

bool check_request(const struct ether_arp *req, struct sockaddr_ll *addr)
{
	if (ntohs(req->ea_hdr.ar_hrd) != ARPHRD_ETHER) {
		XLOG_INFO("check request: invalid hardware address");
		return false;
	}

	if (ntohs(req->ea_hdr.ar_pro) != ETHERTYPE_IP) {
		XLOG_INFO("check request: invalid ethertype");
		return false;
	}

	if (req->ea_hdr.ar_hln != ETH_ALEN) {
		XLOG_INFO("check request: invalid hardware address length");
		return false;
	}

	if (req->ea_hdr.ar_pln != sizeof(in_addr_t)) {
		XLOG_INFO("check request: invalid protocol address length");
		return false;
	}

	if (ntohs(req->ea_hdr.ar_op) != ARPOP_RREQUEST) {
		XLOG_INFO("check request: invalid rarp opcode");
		return false;
	}

	if (memcmp(req->arp_sha, addr->sll_addr, ETH_ALEN) != 0) {
		XLOG_INFO("check request: spoofed src addr");
		return false;
	}

	XLOG_INFO("rarp request for %s from %s",
		ether_ntoa((struct ether_addr*)&req->arp_sha),
		ether_ntoa((struct ether_addr*)&req->arp_tha));

	return true;
}

ssize_t read_request(int fd, struct sockaddr_ll *addr, char *buf, size_t size)
{
	ssize_t ret;
	socklen_t addrlen;
	addrlen = sizeof(struct sockaddr_ll);

	ret = recvfrom(fd, buf, size, 0, (struct sockaddr *)addr, &addrlen);
	if (ret < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			return 0;
		}
		XLOG_ERR("read error on fd %i: %s", fd, strerror(errno));
		return -1;
	}

	XLOG_DEBUG("read %i octets", ret);
	return ret;
}

/*
   This may (and will) block.
   Use local /etc/ethers and /etc/hosts
   to avoid NIS and DNS queries.
 */
int resolve(struct ether_addr *addr, struct in_addr *in_addr)
{
	int ret;
	char hostname[4096];
	struct addrinfo *ai, hints;
	struct sockaddr_in *sa;

	memset(hostname, 0, sizeof(hostname));
	/*
	   This is not really safe, at the time of writing glibc uses
	   a 1024 byte buffer for the answer internally ...  We could
	   parse /etc/ethers by ourselves but then we would loose
	   nsswitch support. Alas RARP support without NIS is no fun :-(
	*/
	ret = ether_ntohost(hostname, addr);
	if (ret != 0) {
		XLOG_INFO("failed to lookup %s", ether_ntoa(addr));
		return -1;
	}

	XLOG_DEBUG("lookup for %s returned %s", ether_ntoa(addr), hostname);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_flags = AI_ADDRCONFIG;
	ai = NULL;
	ret = getaddrinfo(hostname, NULL, &hints, &ai);
	if (ret != 0) {
		XLOG_INFO("could not resolve '%s': %s\n", hostname,
			ret == EAI_SYSTEM ? strerror(errno) : gai_strerror(ret));
		return -1;
	}

	sa = (struct sockaddr_in *)(ai->ai_addr);
	memcpy(in_addr, &(sa->sin_addr), sizeof(struct in_addr));

	return 0;
}

void create_reply(struct ether_arp *reply, struct in_addr *ip, struct link *link)
{
	reply->ea_hdr.ar_op = htons(ARPOP_RREPLY);
	memcpy(&reply->arp_tha, &reply->arp_sha, sizeof(reply->arp_tha));
	memcpy(&reply->arp_tpa, ip, sizeof(reply->arp_tpa));
	memcpy(&reply->arp_sha, &link->ether_addr, sizeof(reply->arp_sha));
	memcpy(&reply->arp_spa, &link->in_addr, sizeof(reply->arp_spa));
}

/* look for a "bootable" file which we can serve via tftp
 * The file must start with the hex encoded ip address
 * and be placed in /tftpboot.
 * An ss4 that is assigned an address of 192.168.77.17
 * for example will try to boot a file named C0A84D11.SUN4M
 */
bool is_bootable(struct in_addr in)
{
	DIR *dir;
	struct dirent *entry;
	char name[9];
	const char bootdir[] = "/tftpboot";

	snprintf(name, sizeof(name), "%08X", ntohl(*(uint32_t*)(&in)));
	XLOG_DEBUG("looking for file matching %s in %s", name, bootdir);

	dir = opendir(bootdir);
	if (dir == NULL) {
		return false;
	}

	do {
		entry = readdir(dir);
	} while (entry != NULL && strncmp(name, entry->d_name, 8) != 0);

	closedir(dir);
	return entry != NULL;
}

void handle_request(struct link *link, bool check_bootable)
{
	int ret;
	ssize_t size;
	struct ether_arp *arp_req;
	struct in_addr ip;

	memset(link->buf, 0, sizeof(link->buf));
	memset(&link->src, 0, sizeof(link->src));

	size = read_request(link->pollfd->fd,
		&link->src, link->buf, sizeof(link->buf));

	if (size <= 0) {
		return;
	}

	if (!check_frame(&link->src, link)) {
		return;
	}

	if ((size_t) size < sizeof(struct ether_arp)) {
		XLOG_INFO("request to short");
		return;
	}

	arp_req = (struct ether_arp *)link->buf;
	if (!check_request(arp_req, &link->src)) {
		return;
	}

	memset(&ip, 0, sizeof(in_addr_t));
	ret = resolve((struct ether_addr*)&arp_req->arp_tha, &ip);
	if (ret != 0) {
		return;
	}

	XLOG_INFO("found address: %s", inet_ntoa(ip));
	if (check_bootable == true && !is_bootable(ip)) {
		return;
	}

	create_reply(arp_req, &ip, link);
	link->pollfd->events = POLLOUT;
}

int send_reply(struct link *link)
{
	ssize_t ret;

	ret = sendto(link->pollfd->fd, link->buf, sizeof(struct ether_arp), 0,
		(struct sockaddr *)&link->src, sizeof(struct sockaddr_ll));

	if (ret < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			return 0;
		}
		XLOG_ERR("write error on fd %i: %s",
			link->pollfd->fd, strerror(errno));
		return -1;
	}

	XLOG_DEBUG("send %i octets on %s", ret, link->name);
	link->pollfd->events = POLLIN;
	return 0;
}

void dispatch_requests(struct rarpd *rarpd, int events)
{
	nfds_t i;
	int processed;
	struct link *link;
	struct pollfd *pollfd;

	processed = 0;
	pollfd = rarpd->fds;
	for (i = 0; i < rarpd->nfds; ++i, ++pollfd) {
		if (pollfd->revents == 0) {
			continue;
		}

		link = find_link_by_fd(pollfd->fd, rarpd->link, rarpd->link_count);
		if (link == NULL) {
			XLOG_ERR("received poll event for unkown link");
			return;
		}

		XLOG_DEBUG("received poll event for %s", link->name);

		if (pollfd->revents & POLLIN) {
			handle_request(link, rarpd->opts & BOOT_FILE);
		} else if (pollfd->revents & POLLOUT) {
			send_reply(link);
		} else {
			XLOG_DEBUG("poll error on %s", link->name);
		}

		pollfd->revents = 0;

		if (++processed == events) {
			return;
		}
	}
}

void poll_loop(struct rarpd *rarpd)
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

void rarpd_init(struct rarpd *rarpd)
{
	memset(rarpd, 0, sizeof(struct rarpd));
	rarpd->nl_ctx.fd = -1;
}

int write_pidfile()
{
	FILE *pidfile;

	pidfile = fopen("/var/run/rarpd.pid", "w");
	if (pidfile == NULL) {
		XLOG_ERR("could not open pidfile: %s", strerror(errno));
		return -1;
	}

	fprintf(pidfile, "%u", getpid());
	fclose(pidfile);

	return 0;
}

int parse_options(struct rarpd* rarpd, int argc, char *argv[])
{
	int opt;

	for (;;) {
		opt = getopt(argc, argv, "adflt");
		switch (opt) {
		case -1:
			return 0;
		case 'a':
			rarpd->opts |= LISTEN_ALL;
			break;
		case 'd':
			rarpd->opts |= (DEBUG_MODE|FOREGROUND);
			break;
		case 'f':
			rarpd->opts |= FOREGROUND;
			break;
		case 'l':
			rarpd->opts |= LOG_REQ;
			break;
		case 't':
			rarpd->opts |= BOOT_FILE;
			break;
		default:
			return -1;
		}
	}
}

int parse_args(struct rarpd* rarpd, char *argv[])
{
	if (rarpd->opts & LISTEN_ALL) {
		if (argv[optind] != NULL) {
			XLOG_ERR("found extra arguments, but -a given");
			return -1;
		}
		return 0;
	}

	if (argv[optind] == NULL) {
		XLOG_ERR("no interfaces specified, use -a for all interfaces");
		return -1;
	}

	rarpd->ifname = &argv[optind];
	return 0;
}

int find_interfaces(struct rarpd *rarpd)
{
	if (nl_open(&rarpd->nl_ctx) != 0) {
		return -1;
	}

	if (get_links(rarpd) != 0) {
		return -1;
	}

	if (get_addresses(rarpd) != 0) {
		return -1;
	}

	nl_close(&rarpd->nl_ctx);
	return 0;
}

int daemonize()
{
	int ret;
	int fd;
	pid_t pid;

	pid = fork();
	if (pid < 0) {
		exit(EXIT_FAILURE);
	}

	if (pid > 0) {
		exit(EXIT_SUCCESS);
	}

	ret = setsid();
	if (ret == -1) {
		XLOG_ERR("failed to set session id: %s", strerror(errno));
		return -1;
	}

	for (fd = getdtablesize(); fd >= 0; --fd) {
		 close(fd);
	}

	chdir("/");

	fd = open("/dev/null", O_RDWR);
	dup(fd);
	dup(fd);

	return 0;
}

int main(int argc, char *argv[])
{
	(void) argc;
	(void) argv;

	struct rarpd rarpd;

	rarpd_init(&rarpd);
	if (parse_options(&rarpd, argc, argv) != 0) {
		return EXIT_FAILURE;
	}

	if (parse_args(&rarpd, argv) != 0) {
		return EXIT_FAILURE;
	}

	openlog("rarpd", LOG_PERROR|LOG_PID, LOG_DAEMON);
	if (find_interfaces(&rarpd) != 0) {
		return EXIT_FAILURE;
	}

	filter_links(&rarpd);
	if (rarpd.link_count == 0) {
		XLOG_ERR("no usable links found");
		return EXIT_FAILURE;
	}

	if (setup_links(&rarpd) != 0) {
		return EXIT_FAILURE;
	}

	if (!(rarpd.opts & FOREGROUND)) {
		if (daemonize() != 0) {
			return EXIT_FAILURE;
		}
	}

	poll_loop(&rarpd);

	free(rarpd.fds);
	free(rarpd.link);

	unlink("/var/run/rarpd.pid");

	return 0;
}
