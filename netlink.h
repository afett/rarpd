#ifndef NETLINK_H
#define NETLINK_H

#include <inttypes.h>
#include <netinet/in.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

struct nl_ctx {
	int fd;
	struct sockaddr_nl sa;
};

struct nl_cb;
struct ether_addr;
struct in_addr_t;

struct nl_link {
	int ifindex;
	unsigned short iftype;
	unsigned int ifflags;
	const char *ifname;
	const struct ether_addr *ifaddr;
};

struct nl_addr {
	int ifindex;
	in_addr_t ifaddr;
};

typedef void (*nl_link_cb)(struct nl_link*, void *);
typedef void (*nl_addr_cb)(struct nl_addr*, void *);
typedef void (*nl_msg_parse)(struct nlmsghdr *nlp, struct nl_cb *);

struct nl_cb {
	uint16_t msg_type;
	nl_msg_parse parse_msg;
	void (*parse_cb)(void);
	void *aux;
};

int nl_open(struct nl_ctx *nl_ctx);
void nl_close(struct nl_ctx *nl_ctx);
int nl_receive(struct nl_ctx *nl_ctx, struct nl_cb *cb);
void nl_init_link_cb(struct nl_cb *nl_cb, nl_link_cb link_cb, void *aux);
int nl_list_links(struct nl_ctx *nl_ctx);
void nl_init_addr_cb(struct nl_cb *nl_cb, nl_addr_cb addr_cb, void *aux);
int nl_list_addr(struct nl_ctx *nl_ctx);
int nl_set_neigh(struct nl_ctx *nl_ctx, size_t index, struct ether_addr *ether_addr, in_addr_t *in_addr);

#endif
