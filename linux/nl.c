/*
 * Netlink setup, based on code originally from the iw utility.
 *
 * Copyright (c) 2007, 2008	Johannes Berg
 * Copyright (c) 2007		Andy Lutomirski
 * Copyright (c) 2007		Mike Kershaw
 * Copyright (c) 2008-2009		Luis R. Rodriguez
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#include <errno.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/genl.h>
#include <netlink/msg.h>
#include <netlink/netlink.h>
#include <netlink/socket.h>

#include "nl.h"

static int
error_handler(struct sockaddr_nl *nla, struct nlmsgerr *err, void *arg) {
  int *ret = arg;
  *ret = err->error;
  return NL_STOP;
}

static int ack_handler(struct nl_msg *msg, void *arg) {
  int *ret = arg;
  if (ret)
    *ret = 0;
  return NL_STOP;
}

struct multicast_query {
  const char *name;
  int group_id;
};

static int multicast_handler(struct nl_msg *msg, void *arg) {
  struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
  struct multicast_query *query = arg;
  struct nlattr *tb[CTRL_ATTR_MAX + 1];
  struct nlattr *mcgrp;
  int i;

  nla_parse(
      tb,
      CTRL_ATTR_MAX,
      genlmsg_attrdata(gnlh, 0),
      genlmsg_attrlen(gnlh, 0),
      NULL);

  if (!tb[CTRL_ATTR_MCAST_GROUPS])
    return NL_SKIP;

  nla_for_each_nested(mcgrp, tb[CTRL_ATTR_MCAST_GROUPS], i) {
    struct nlattr *tb2[CTRL_ATTR_MCAST_GRP_MAX + 1];
    nla_parse(
        tb2, CTRL_ATTR_MCAST_GRP_MAX, nla_data(mcgrp), nla_len(mcgrp), NULL);
    if (tb2[CTRL_ATTR_MCAST_GRP_NAME] && tb2[CTRL_ATTR_MCAST_GRP_ID]) {
      if (!nla_strcmp(tb2[CTRL_ATTR_MCAST_GRP_NAME], query->name)) {
        query->group_id = nla_get_u32(tb2[CTRL_ATTR_MCAST_GRP_ID]);
        break;
      }
    }
  };

  return NL_SKIP;
}

static int
get_multicast_id(struct nl_sock *sock, const char *family, const char *group) {
  struct multicast_query query = {.name = group, .group_id = -1};
  struct nl_msg *msg;
  int ret = -ENOMEM;
  struct nl_cb *cb;

  msg = nlmsg_alloc();
  if (!msg)
    return -ENOMEM;

  if (!genlmsg_put(
          msg,
          0,
          NL_AUTO_SEQ,
          genl_ctrl_resolve(sock, "nlctrl"),
          0,
          0,
          CTRL_CMD_GETFAMILY,
          0))
    goto nla_put_failure;

  NLA_PUT_STRING(msg, CTRL_ATTR_FAMILY_NAME, family);

  // setup callback
  cb = nl_cb_alloc(NL_CB_DEFAULT);
  if (!cb)
    goto out;

  nl_cb_err(cb, NL_CB_CUSTOM, error_handler, &ret);
  nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &ret);
  nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, multicast_handler, &query);

  // send and receive request
  ret = nl_send_auto_complete(sock, msg);
  if (ret < 0)
    goto out_free_cb;

  ret = 1;
  while (ret > 0)
    nl_recvmsgs(sock, cb);

  if (ret == 0)
    ret = query.group_id;

out_free_cb:
  nl_cb_put(cb);
out:
nla_put_failure:
  nlmsg_free(msg);
  return ret;
}

static int
add_membership(struct netlink_ctx *ctx, const char *family, const char *group) {
  int ret = get_multicast_id(ctx->cmd_sock, family, group);
  if (ret >= 0)
    ret = nl_socket_add_membership(ctx->cmd_sock, ret);
  return ret;
}

struct netlink_ctx *netlink_setup(
    int (*nl_cb)(struct nl_msg *, void *),
    nl_recvmsg_err_cb_t nl_err_cb,
    void *data) {
  int err;
  struct netlink_ctx *ctx;

  ctx = malloc(sizeof(*ctx));
  if (!ctx)
    return NULL;

  /* allocate config/event sockets and connect to generic netlink */
  ctx->cmd_sock = nl_socket_alloc();
  if (!ctx->cmd_sock) {
    fprintf(stderr, "Failed to allocate netlink socket.\n");
    goto out_free;
  }

  if (genl_connect(ctx->cmd_sock)) {
    fprintf(stderr, "Failed to connect to generic netlink.\n");
    goto out_handle_destroy;
  }

  ctx->nl80211_id = genl_ctrl_resolve(ctx->cmd_sock, "nl80211");
  if (ctx->nl80211_id < 0) {
    fprintf(stderr, "nl80211 not found.\n");
    goto out_handle_destroy;
  }

  nl_socket_set_buffer_size(ctx->cmd_sock, 1024 * 256, 1024 * 256);

  /* get extended ack reporting */
  err = 1;
  setsockopt(
      nl_socket_get_fd(ctx->cmd_sock),
      SOL_NETLINK,
      NETLINK_EXT_ACK,
      &err,
      sizeof(err));

  /* subscribe to multicast events */
  if (add_membership(ctx, "nl80211", "scan")) {
    fprintf(stderr, "failed to join scan group\n");
    goto out_handle_destroy;
  }

  if (add_membership(ctx, "nl80211", "mlme")) {
    fprintf(stderr, "failed to join mlme group\n");
    goto out_handle_destroy;
  }

  /* must disable sequence checking for events */
  nl_socket_disable_seq_check(ctx->cmd_sock);

  /* set callbacks */
  nl_socket_modify_cb(ctx->cmd_sock, NL_CB_VALID, NL_CB_CUSTOM, nl_cb, data);
  nl_socket_modify_err_cb(ctx->cmd_sock, NL_CB_CUSTOM, nl_err_cb, data);

  return ctx;

out_handle_destroy:
  nl_socket_free(ctx->cmd_sock);
out_free:
  free(ctx);
  return NULL;
}

void netlink_destroy(struct netlink_ctx *ctx) {
  if (!ctx)
    return;

  nl_socket_free(ctx->cmd_sock);
  free(ctx);
}
