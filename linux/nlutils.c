/*
 * Copyright (c) 2010, cozybit Inc.
 * Javier Cardona, javier@cozybit.com
 *
 * Functions from this file have been liberally copied from libnl
 * documentation and wpa_supplicant. wpa_supplicant is licensed under
 * GPL and has the following copyrights:
 *
 *  Copyright (c) 2002-2010, Jouni Malinen <j@w1.fi>
 *  Copyright (c) 2003-2004, Instant802 Networks, Inc.
 *  Copyright (c) 2005-2006, Devicescape Software, Inc.
 *  Copyright (c) 2007, Johannes Berg <johannes@sipsolutions.net>
 *  Copyright (c) 2009-2010, Atheros Communications
 *
 * cozybit Inc. makes no claim that this file can be linked against
 * authsae and provides no warranties on this file.  If you decide to
 * use it, do it at your own risk.
 *
 */

#include "nlutils.h"

static int ack_handler(struct nl_msg *msg, void *arg)
{
    int *err = arg;
    *err = 0;
    return NL_STOP;
}

static int finish_handler(struct nl_msg *msg, void *arg)
{
    int *ret = arg;
    *ret = 0;
    return NL_SKIP;
}

static int error_handler(struct sockaddr_nl *nla, struct nlmsgerr *err,
        void *arg)
{
    struct netlink_config_s *nlcfg = arg;
    struct genlmsghdr *gnlh = nlmsg_data(&err->msg);

    if (arg && err && nlcfg->supress_error &&
            nlcfg->supress_error != err->error) {
        fprintf(stderr, "Unexpected error %d ", err->error);
        fprintf(stderr, "(expected %d)\n", nlcfg->supress_error);
    } else {
	    fprintf(stderr, "nlerror, cmd %d, seq %d: %s\n", gnlh->cmd, err->msg.nlmsg_seq,
							     strerror(abs(err->error)));
    }
    nlcfg->supress_error = 0;
    return NL_SKIP;
}

static int simple_error_handler(struct sockaddr_nl *nla, struct nlmsgerr *err,
                                void *arg)
{
    int *ret = arg;
    *ret = 0;
    if (arg && err) {
        *ret = err->error;
        if (*ret != 0)
            return NL_STOP;
    }
    return NL_SKIP;
}

int send_nlmsg(struct nl_sock *nl_sock, struct nl_msg *msg)
{
        int err = -ENOMEM;

        err = nl_send_auto_complete(nl_sock, msg);

        nlmsg_free(msg);
        return err;
}

static int send_and_recv(struct nl_sock *nl_sock, struct nl_msg *msg,
                         int (*valid_handler)(struct nl_msg *, void *),
                         void *valid_data)
{
        struct nl_cb *cb;
        int err = -ENOMEM;

        cb = nl_cb_clone(nl_socket_get_cb(nl_sock));
        if (!cb)
                goto out;

        err = nl_send_auto_complete(nl_sock, msg);
        if (err < 0)
                goto out;

        err = 1;

        nl_cb_err(cb, NL_CB_CUSTOM, simple_error_handler, &err);
        nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &err);
        nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &err);


        if (valid_handler)
                nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM,
                          valid_handler, valid_data);

        while (err > 0)
                nl_recvmsgs(nl_sock, cb);
 out:
        nl_cb_put(cb);
        nlmsg_free(msg);
        return err;
}

struct family_data {
        const char *group;
        int id;
};

static int family_handler(struct nl_msg *msg, void *arg)
{
        struct family_data *res = arg;
        struct nlattr *tb[CTRL_ATTR_MAX + 1];
        struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
        struct nlattr *mcgrp;
        int i;

        nla_parse(tb, CTRL_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
                  genlmsg_attrlen(gnlh, 0), NULL);
        if (!tb[CTRL_ATTR_MCAST_GROUPS])
                return NL_SKIP;

        nla_for_each_nested(mcgrp, tb[CTRL_ATTR_MCAST_GROUPS], i) {
                struct nlattr *tb2[CTRL_ATTR_MCAST_GRP_MAX + 1];
                nla_parse(tb2, CTRL_ATTR_MCAST_GRP_MAX, nla_data(mcgrp),
                          nla_len(mcgrp), NULL);
                if (!tb2[CTRL_ATTR_MCAST_GRP_NAME] ||
                    !tb2[CTRL_ATTR_MCAST_GRP_ID] ||
                    strncmp(nla_data(tb2[CTRL_ATTR_MCAST_GRP_NAME]),
                               res->group,
                               nla_len(tb2[CTRL_ATTR_MCAST_GRP_NAME])) != 0)
                        continue;
                res->id = nla_get_u32(tb2[CTRL_ATTR_MCAST_GRP_ID]);
                break;
        };

        return NL_SKIP;
}

static int nl_get_multicast_id(struct nl_sock *nl_sock, const char
        *family, const char *group) {
	struct nl_msg *msg;
	int ret = -1;
	struct family_data res = { group, -ENOENT };

	msg = nlmsg_alloc();
	if (!msg)
		return -ENOMEM;
	genlmsg_put(msg, 0, 0, genl_ctrl_resolve(nl_sock,
		"nlctrl"), 0, 0, CTRL_CMD_GETFAMILY, 0);
	NLA_PUT_STRING(msg, CTRL_ATTR_FAMILY_NAME, family);

	ret = send_and_recv(nl_sock, msg, family_handler, &res);
	msg = NULL;
	if (ret == 0)
		ret = res.id;

nla_put_failure:
	return ret;
}

int netlink_init(struct netlink_config_s *nlcfg, void *event_handler)
{
	int ret;
    struct nl_cb *cb;

    //nl_debug = 4;

    /* Allocate nl socket for commands with default callback */
	nlcfg->nl_sock = nl_socket_alloc();
	if (nlcfg->nl_sock == NULL) {
		printf("Failed to allocate netlink socket");
		goto err1;
	}

    cb = nl_socket_get_cb(nlcfg->nl_sock);

    if (cb == NULL) {
        goto err2;
    }

    /* Allocate nl socket for events, same callback */
	nlcfg->nl_sock_event = nl_socket_alloc_cb(cb);

	if (nlcfg->nl_sock_event == NULL) {
		printf("Failed to allocate netlink event socket");
		goto err2;
	}

    /* Connect both sockets to generic netlink on kernel side */
	if (genl_connect(nlcfg->nl_sock)) {
		printf("Failed to connect to generic netlink");
		goto err3;
	}

	if (genl_connect(nlcfg->nl_sock_event)) {
		printf("Failed to connect events to generic netlink");
		goto err3;
	}

    /* Increase the default buffer size on both sockets */
#define NL_SOCKET_BUFFER_SIZE   (1024 * 256)
    ret = nl_socket_set_buffer_size(nlcfg->nl_sock_event, NL_SOCKET_BUFFER_SIZE, NL_SOCKET_BUFFER_SIZE);
    if (ret)
        fprintf(stderr, "nl_socket_set_buffer_size failed with error %d, errno %d)\n", ret, errno);

    ret = nl_socket_set_buffer_size(nlcfg->nl_sock, NL_SOCKET_BUFFER_SIZE, NL_SOCKET_BUFFER_SIZE);
    if (ret)
        fprintf(stderr, "nl_socket_set_buffer_size failed with error %d, errno %d)\n", ret, errno);

    /* Allocate caches for each socket */
	if (genl_ctrl_alloc_cache(nlcfg->nl_sock, &nlcfg->nl_cache) < 0) {
		printf("Failed to allocate generic netlink cache");
		goto err3;
	}

	if (genl_ctrl_alloc_cache(nlcfg->nl_sock_event, &nlcfg->nl_cache_event) <
	    0) {
		printf("Failed to allocate events cache");
		goto err3b;
	}

    /* Find nl80211 family in the generic netlink cache */
	nlcfg->nl80211 = genl_ctrl_search_by_name(nlcfg->nl_cache, "nl80211");
	if (nlcfg->nl80211 == NULL) {
		printf("'nl80211' generic netlink not found");
		goto err4;
	}

    /* Register events socket for multicast mlme events */
	ret = nl_get_multicast_id(nlcfg->nl_sock, "nl80211", "mlme");
	if (ret >= 0)
		ret = nl_socket_add_membership(nlcfg->nl_sock_event, ret);

	if (ret < 0) {
		printf("Could not add multicast "
			   "membership for mlme events: %d (%s)",
			   ret, strerror(-ret));
		goto err4;
	}

    /* Register for scan events */
	ret = nl_get_multicast_id(nlcfg->nl_sock, "nl80211", "scan");
	if (ret >= 0)
		ret = nl_socket_add_membership(nlcfg->nl_sock_event, ret);

	if (ret < 0) {
		printf("Could not add multicast "
			   "membership for scan events: %d (%s)",
			   ret, strerror(-ret));
		goto err4;
	}

    /* Sequence checking needs to be disabled for events.  Note that
     * this will also disable it for on the commands socket, given
     * that they share the same callback. */
    nl_socket_disable_seq_check(nlcfg->nl_sock);

    /* Register our callback function for valid messages */
    nl_socket_modify_cb(nlcfg->nl_sock, NL_CB_VALID, NL_CB_CUSTOM,
            event_handler, &nlcfg);

    /* print errors */
    nl_cb_err(cb, NL_CB_CUSTOM, error_handler, nlcfg);

	return 0;

err4:
	nl_cache_free(nlcfg->nl_cache_event);
err3b:
	nl_cache_free(nlcfg->nl_cache);
err3:
	nl_socket_free(nlcfg->nl_sock_event);
err2:
	nl_socket_free(nlcfg->nl_sock);
err1:
	return -1;
}
