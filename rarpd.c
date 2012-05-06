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

#include <fcntl.h>
#include <netdb.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>

#include "dispatcher.h"
#include "link.h"
#include "netlink.h"
#include "sighandler.h"
#include "xlog.h"

#define PIDFILE "/var/run/rarpd.pid"

enum {
	LISTEN_ALL = 1 << 0,
	DEBUG_MODE = 1 << 1,
	FOREGROUND = 1 << 2,
	LOG_REQ    = 1 << 3,
	BOOT_FILE  = 1 << 4,
};

struct rarpd {
	struct nl_ctx nl_ctx;
	struct link_array links;
	struct dispatcher dispatcher;
	struct poll_handler *sighandler;
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

void add_link(struct nl_link *nl_link, void *aux)
{
	struct rarpd *rarpd;
	struct link *link;

	rarpd = (struct rarpd *) aux;
	if (!(rarpd->opts & LISTEN_ALL) && !in_argv(nl_link->ifname, rarpd->ifname)) {
		XLOG_DEBUG("skipping %s: not found in arguments", nl_link->ifname);
		return;
	}

	if (nl_link->iftype != ARPHRD_ETHER) {
		XLOG_DEBUG("skipping %s: no ethernet", nl_link->ifname);
		return;
	}

	if (!(nl_link->ifflags & IFF_RUNNING)) {
		XLOG_DEBUG("skipping %s: link is down", nl_link->ifname);
		return;
	}

	XLOG_DEBUG("adding link %s: %s",
		nl_link->ifname, ether_ntoa(nl_link->ifaddr));
	link = link_array_add(&rarpd->links);
	link->ifindex = nl_link->ifindex;
	snprintf(link->name, sizeof(link->name), "%s", nl_link->ifname);
	memcpy(&link->ether_addr, nl_link->ifaddr, sizeof(struct ether_addr));
	link->in_addr = 0;
}

bool link_add_addr(struct link* link, void *aux)
{
	struct nl_addr *nl_addr;
	char addrstr[INET_ADDRSTRLEN];
	char used[INET_ADDRSTRLEN];

	nl_addr = (struct nl_addr *) aux;
	if (link->ifindex != nl_addr->ifindex) {
		return true;
	}

	inet_ntop(AF_INET, &nl_addr->ifaddr, addrstr, sizeof(addrstr));
	if (link->in_addr != 0) {
		inet_ntop(AF_INET, &link->in_addr, used, sizeof(used));
		XLOG_WARNING("ignoring address %s for link %s using %s",
			addrstr, link->name, used);
		return true;
	}

	XLOG_DEBUG("using address %s for link %s", addrstr, link->name);
	link->in_addr = nl_addr->ifaddr;
	return true;
}

void add_addr(struct nl_addr *addr, void *aux)
{
	struct link_array *links;

	links = (struct link_array *) aux;
	link_array_foreach(links, link_add_addr, addr);
}

int get_addresses(struct rarpd *rarpd)
{
	struct nl_cb cb;

	if (nl_list_addr(&rarpd->nl_ctx) != 0) {
		return -1;
	}

	nl_init_addr_cb(&cb, add_addr, &rarpd->links);
	return nl_receive(&rarpd->nl_ctx, &cb);
}

bool has_addr(struct link *link, void *aux)
{
	(void) aux;
	return link->in_addr != 0;
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

enum dispatch_action
rarp_handler(int fd, short events, void *aux);

bool setup_link(struct link *link, void *aux)
{
	int fd;
	struct dispatcher *dispatcher;

	fd = open_socket();
	if (fd < 0) {
		goto err;
	}

	if (do_bind(fd, link->ifindex) != 0) {
		goto err;
	}

	if (set_promisc(fd, link->ifindex) != 0) {
		goto err;
	}

	dispatcher = (struct dispatcher *) aux;
	link->handler = dispatcher_watch(
		dispatcher, fd, rarp_handler, link);
	link->handler->events = POLLIN;

	return true;
err:
	close(fd);
	XLOG_ERR("error setting up %s", link->name);
	return false;
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
		XLOG_WARNING(
			"frame check failed: no RARP packet: sll_protocol=0x%x",
			ntohs(addr->sll_protocol));
		return false;
	}

	if (addr->sll_ifindex != link->ifindex) {
		XLOG_WARNING("frame check failed: wrong interface");
		return false;
	}

	if (addr->sll_hatype != ARPHRD_ETHER) {
		XLOG_WARNING("frame check failed: no ethernet");
		return false;
	}

	if (addr->sll_pkttype != PACKET_BROADCAST) {
		XLOG_WARNING("frame check failed: no broadcast");
		return false;
	}

	if (addr->sll_halen != sizeof(struct ether_addr)) {
		XLOG_WARNING("frame check failed: bad source address length");
		return false;
	}

	return true;
}

bool check_request(const struct ether_arp *req, struct sockaddr_ll *addr)
{
	if (ntohs(req->ea_hdr.ar_hrd) != ARPHRD_ETHER) {
		XLOG_WARNING("check request: invalid hardware address");
		return false;
	}

	if (ntohs(req->ea_hdr.ar_pro) != ETHERTYPE_IP) {
		XLOG_WARNING("check request: invalid ethertype");
		return false;
	}

	if (req->ea_hdr.ar_hln != ETH_ALEN) {
		XLOG_WARNING("check request: invalid hardware address length");
		return false;
	}

	if (req->ea_hdr.ar_pln != sizeof(in_addr_t)) {
		XLOG_WARNING("check request: invalid protocol address length");
		return false;
	}

	if (ntohs(req->ea_hdr.ar_op) != ARPOP_RREQUEST) {
		XLOG_WARNING("check request: invalid rarp opcode");
		return false;
	}

	if (memcmp(req->arp_sha, addr->sll_addr, ETH_ALEN) != 0) {
		XLOG_WARNING("check request: spoofed src addr");
		return false;
	}

	XLOG_DEBUG("rarp request for %s from %s",
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
		XLOG_DEBUG("failed to lookup %s", ether_ntoa(addr));
		return -1;
	}

	XLOG_DEBUG("lookup for %s returned %s", ether_ntoa(addr), hostname);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_flags = AI_ADDRCONFIG;
	ai = NULL;
	ret = getaddrinfo(hostname, NULL, &hints, &ai);
	if (ret != 0) {
		XLOG_DEBUG("could not resolve '%s': %s\n", hostname,
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

void handle_request(int fd, struct link *link, bool check_bootable)
{
	int ret;
	ssize_t size;
	struct ether_arp *arp_req;
	struct in_addr ip;

	memset(link->buf, 0, sizeof(link->buf));
	memset(&link->src, 0, sizeof(link->src));

	size = read_request(fd,
		&link->src, link->buf, sizeof(link->buf));

	if (size <= 0) {
		return;
	}

	if (!check_frame(&link->src, link)) {
		return;
	}

	if ((size_t) size < sizeof(struct ether_arp)) {
		XLOG_WARNING("request to short");
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

	XLOG_DEBUG("found address: %s", inet_ntoa(ip));
	if (check_bootable == true && !is_bootable(ip)) {
		return;
	}

	create_reply(arp_req, &ip, link);
	link->handler->events = POLLOUT;
}

int send_reply(int fd, struct link *link)
{
	ssize_t ret;

	ret = sendto(fd, link->buf, sizeof(struct ether_arp), 0,
		(struct sockaddr *)&link->src, sizeof(struct sockaddr_ll));

	if (ret < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			return 0;
		}
		XLOG_ERR("write error on fd %i: %s", fd, strerror(errno));
		return -1;
	}

	XLOG_DEBUG("send %i octets on %s", ret, link->name);
	link->handler->events = POLLIN;
	return 0;
}

enum dispatch_action
rarp_handler(int fd, short events, void *aux)
{
	struct link *link;

	link = (struct link*) aux;
	XLOG_DEBUG("received poll event for %s", link->name);

	if (events & POLLIN) {
		handle_request(fd, link, false);
	} else if (events & POLLOUT) {
		send_reply(fd, link);
	} else {
		XLOG_DEBUG("poll error on %s", link->name);
	}

	return DISPATCH_CONTINUE;
}

enum dispatch_action
signal_handler(int fd, short events, void *aux)
{
	(void) events;
	(void) aux;

	int signo;
	int ret;

	signo = 0;
	do {
		ret = read(fd, &signo, sizeof(signo));
	} while (ret < 0 && errno == EINTR);

	XLOG_INFO("caught signal: %s terminating", strsignal(signo));

	return DISPATCH_ABORT;
}

void rarpd_init(struct rarpd *rarpd)
{
	memset(rarpd, 0, sizeof(struct rarpd));
	rarpd->nl_ctx.fd = -1;
	dispatcher_init(&rarpd->dispatcher);
}

int rarpd_init_signals(struct rarpd *rarpd)
{
	int signalfd;

	signalfd = install_signal_fd();
	if (signalfd < 0) {
		return -1;
	}

	rarpd->sighandler = dispatcher_watch(
		&rarpd->dispatcher, signalfd, signal_handler, NULL);
	rarpd->sighandler->events = POLLIN;
	return 0;
}

int write_pidfile()
{
	int fd;
	FILE *pidfile;

	fd = open(PIDFILE, O_WRONLY|O_CLOEXEC|O_CREAT|O_EXCL, 0644);
	if (fd < 0) {
		XLOG_ERR("could not open pidfile: %s", strerror(errno));
		return -1;
	}

	pidfile = fdopen(fd, "w");
	if (pidfile == NULL) {
		XLOG_ERR("could not fdopen pidfile: %s", strerror(errno));
		return -1;
	}

	fprintf(pidfile, "%u", getpid());
	fclose(pidfile);

	return 0;
}

void usage(const char* msg)
{
	if (msg != NULL) {
		fprintf(stderr, "%s\n", msg);
	}
	fprintf(stderr, "Usage: rarpd [-adflt] interface ...\n");
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
			usage(NULL);
			return -1;
		}
	}
}

int parse_args(struct rarpd* rarpd, char *argv[])
{
	if (rarpd->opts & LISTEN_ALL) {
		if (argv[optind] != NULL) {
			usage("found extra arguments, but -a given");
			return -1;
		}
		return 0;
	}

	if (argv[optind] == NULL) {
		usage("no interfaces specified, use -a for all interfaces");
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

	if (write_pidfile() != 0) {
		return -1;
	}

	ret = setsid();
	if (ret == -1) {
		XLOG_ERR("failed to set session id: %s", strerror(errno));
		unlink(PIDFILE);
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

void cleanup_rarpd(struct rarpd *rarpd)
{
	unlink(PIDFILE);
	link_array_free(&rarpd->links);
	dispatcher_cleanup(&rarpd->dispatcher);
}

void init_syslog(struct rarpd *rarpd)
{
	int logopt;

	logopt = LOG_PID;
	if (rarpd->opts & DEBUG_MODE) {
		logopt |= LOG_PERROR;
	}
	openlog("rarpd", logopt, LOG_DAEMON);

	if (!(rarpd->opts & DEBUG_MODE)) {
		setlogmask(LOG_UPTO(LOG_INFO));
	}
}

int rarpd(int argc, char *argv[])
{
	struct rarpd rarpd;

	rarpd_init(&rarpd);

	if (parse_options(&rarpd, argc, argv) != 0) {
		return EXIT_FAILURE;
	}

	if (parse_args(&rarpd, argv) != 0) {
		return EXIT_FAILURE;
	}

	if (!(rarpd.opts & FOREGROUND) && daemonize() != 0) {
		return EXIT_FAILURE;
	}

	init_syslog(&rarpd);

	if (rarpd_init_signals(&rarpd) != 0) {
		return EXIT_FAILURE;
	}

	if (find_interfaces(&rarpd) != 0) {
		return EXIT_FAILURE;
	}

	link_array_filter(&rarpd.links, has_addr, NULL);
	if (rarpd.links.count == 0) {
		XLOG_ERR("no usable links found");
		return EXIT_FAILURE;
	}

	if (!link_array_foreach(&rarpd.links, setup_link, &rarpd.dispatcher)) {
		cleanup_rarpd(&rarpd);
		return EXIT_FAILURE;
	}

	dispatcher_run(&rarpd.dispatcher);

	cleanup_rarpd(&rarpd);
	return EXIT_SUCCESS;
}
