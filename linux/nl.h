#ifndef __NL_H
#define __NL_H

#include <netlink/genl/ctrl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/genl.h>
#include <netlink/msg.h>
#include <netlink/netlink.h>
#include <netlink/socket.h>

#ifndef NETLINK_EXT_ACK
#define NETLINK_EXT_ACK 11
enum nlmsgerr_attrs {
	NLMSGERR_ATTR_UNUSED,
	NLMSGERR_ATTR_MSG,
	NLMSGERR_ATTR_OFFS,
	NLMSGERR_ATTR_COOKIE,

	__NLMSGERR_ATTR_MAX,
	NLMSGERR_ATTR_MAX = __NLMSGERR_ATTR_MAX - 1
};
#endif
#ifndef NLM_F_CAPPED
#define NLM_F_CAPPED 0x100
#endif
#ifndef NLM_F_ACK_TLVS
#define NLM_F_ACK_TLVS 0x200
#endif

struct netlink_ctx {
  struct nl_sock *cmd_sock;
  int nl80211_id;
  int ifindex;
};

struct netlink_ctx *netlink_setup(
    int (*nl_cb)(struct nl_msg *, void *),
    nl_recvmsg_err_cb_t nl_err_cb,
    void *data);

void netlink_destroy(struct netlink_ctx *ctx);
#endif /* __NL_H */
