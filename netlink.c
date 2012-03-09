#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <inttypes.h>
#include <unistd.h>
#include <net/ethernet.h>
#include "xlog.h"
#include "netlink.h"

static size_t nl_create_msg(char *buf, size_t size, uint16_t type, uint16_t flags, int family);
static void nl_parse_addr_msg(struct nlmsghdr *nlp, struct nl_cb *cb);
static void nl_parse_link_msg(struct nlmsghdr *nlp, struct nl_cb *cb);
static bool nl_parse(char *buf, ssize_t len, struct nl_cb *cb);
#if 0
static bool nl_add_attr(struct nlmsghdr *nlm, unsigned short type, size_t len, void *data);
#endif

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

void nl_init_link_cb(struct nl_cb *nl_cb, nl_link_cb link_cb, void *aux)
{
	nl_cb->msg_type = RTM_NEWLINK;
	nl_cb->parse_msg = nl_parse_link_msg;
	nl_cb->parse_cb = link_cb;
	nl_cb->aux = aux;
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

void nl_init_addr_cb(struct nl_cb *nl_cb, nl_addr_cb addr_cb, void *aux)
{
	nl_cb->msg_type = RTM_NEWADDR;
	nl_cb->parse_msg = nl_parse_addr_msg;
	nl_cb->parse_cb = addr_cb;
	nl_cb->aux = aux;
}

int nl_list_addr(struct nl_ctx *nl_ctx)
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

int nl_set_neigh(struct nl_ctx *nl_ctx, size_t index, struct ether_addr *ether_addr, in_addr_t *in_addr)
{
	int ret;
	size_t size;
	char buf[1024];

	size = nl_create_msg(buf, sizeof(buf), RTM_NEWNEIGH,
		NLM_F_REQUEST|NLM_F_REPLACE|NLM_F_CREATE, PF_INET);
	// nl_add_attr((struct nlmsghdr *) data, NDA_DST, sizeof(in_addr_r), in_addr);
	// nl_add_attr((struct nlmsghdr *) data, NDA_LLADDR, sizeof(struct ether_addr), ether_addr);
	// fill in ndm_ifindex from link
	// set ndm_state NUD_PERMANENT

	ret = send(nl_ctx->fd, buf, size, 0);
	if (ret != size) {
		XLOG_ERR("error sending netlink message: %s", strerror(errno));
		return -1;
	}

	return 0;
}

static size_t nl_create_msg(char *buf, size_t size, uint16_t type, uint16_t flags, int family)
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

static void nl_parse_link_msg(struct nlmsghdr *nlp, struct nl_cb *cb)
{
	nl_link_cb link_cb;
	struct ifinfomsg *ifinfo;
	struct rtattr *rtap;
	char *name;
	struct ether_addr *addr;
	size_t len;

	name = NULL;
	addr = NULL;
	ifinfo = NLMSG_DATA(nlp);
	rtap = IFLA_RTA(ifinfo);
	len = IFLA_PAYLOAD(nlp);

	for (; RTA_OK(rtap, len); rtap = RTA_NEXT(rtap, len)) {
		switch (rtap->rta_type) {
		case IFLA_IFNAME:
			name = (char *)RTA_DATA(rtap);
			break;
		case IFLA_ADDRESS:
			if (RTA_PAYLOAD(rtap) != sizeof(struct ether_addr)) {
				XLOG_ERR("invalid ll address for %u", ifinfo->ifi_index);
				return;
			}
			addr = (struct ether_addr *)RTA_DATA(rtap);
			break;
		default:
			/* XLOG_DEBUG("attr: %u", rtap->rta_type); */
			break;
		}
	}

	if (!name) {
		XLOG_ERR("could not get name for link %u", ifinfo->ifi_index);
		return;
	}

	if (!addr) {
		XLOG_ERR("could not get ll addr for link %u", ifinfo->ifi_index);
		return;
	}

	link_cb = (nl_link_cb) cb->parse_cb;
	link_cb(ifinfo->ifi_index, ifinfo->ifi_type, ifinfo->ifi_flags, addr, name, cb->aux);
}

static void nl_parse_addr_msg(struct nlmsghdr *nlp, struct nl_cb *cb)
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

static bool nl_parse(char *buf, ssize_t len, struct nl_cb *cb)
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

#if 0
static bool nl_add_attr(struct nlmsghdr *nlm, unsigned short type, size_t len, void *data)
{
	size_t offs = NLMSG_ALIGN(nlm->nlmsg_len);
	struct rtattr *rta = (struct rtattr *) ((char*) nlm + offs);
	rta->rta_type = type;
	rta->rta_len = RTA_LENGTH(len);

	memcpy(RTA_DATA(rta), data, len);
	nlm->nlmsg_len = NLMSG_ALIGN(nlm->nlmsg_len) + RTA_LENGTH(len);
	return RTA_OK(rta, RTA_LENGTH(len));
}
#endif
