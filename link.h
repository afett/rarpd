#ifndef RARPD_LINK_H
#define RARPD_LINK_H

#include <stdbool.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/ether.h>
#include <netpacket/packet.h>

struct poll_handler;

struct link {
	int ifindex;
	char name[IF_NAMESIZE + 1];
	in_addr_t in_addr;
	struct ether_addr ether_addr;
	struct poll_handler *handler;
	struct sockaddr_ll src;
	char buf[1500];
};

struct link_array {
	size_t count;
	struct link *link;
};

typedef bool link_array_fun(struct link *, void *);
typedef bool link_array_keep(struct link *, void *);

struct link* link_array_add(struct link_array *links);
bool link_array_foreach(struct link_array *links, link_array_fun *fun, void *aux);
void link_array_filter(struct link_array *links, link_array_keep *keep, void *aux);
void link_array_free(struct link_array *links);

#endif
