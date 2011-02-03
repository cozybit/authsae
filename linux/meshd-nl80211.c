/*
 * Copyright (c) Dan Harkins, 2008, 2009, 2010
 * Copyright (c) 2010, cozybit Inc.
 *
 *
 *  Copyright holder grants permission for redistribution and use in source
 *  and binary forms, with or without modification, provided that the
 *  following conditions are met:
 *     1. Redistribution of source code must retain the above copyright
 *        notice, this list of conditions, and the following disclaimer
 *        in all source files.
 *     2. Redistribution in binary form must retain the above copyright
 *        notice, this list of conditions, and the following disclaimer
 *        in the documentation and/or other materials provided with the
 *        distribution.
 *     3. All advertising materials and documentation mentioning features
 *      or use of this software must display the following acknowledgement:
 *
 *        "This product includes software written by
 *         Dan Harkins (dharkins at lounge dot org)"
 *
 *  "DISCLAIMER OF LIABILITY
 *
 *  THIS SOFTWARE IS PROVIDED BY DAN HARKINS ``AS IS'' AND
 *  ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 *  THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 *  PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE INDUSTRIAL LOUNGE BE LIABLE
 *  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 *  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 *  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 *  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 *  LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 *  OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 *  SUCH DAMAGE."
 *
 * This license and distribution terms cannot be changed. In other words,
 * this code cannot simply be copied and put under a different distribution
 * license (including the GNU public license).
 */

#include <unistd.h>
#include <sys/select.h>
#include <stdlib.h>
#include <string.h>
#include <net/if.h>
#include <assert.h>

#include "nlutils.h"

/* authsae's event loop */
#include "service.h"

/* Runtime config variables */
static char *ifname = NULL;
struct netlink_config_s nlcfg;
service_context srvctx;

static void srv_handler_wrapper(int fd, void *data) {
    if (nl_recvmsgs_default((struct nl_sock *) data))
        fprintf(stderr, "nl_recvmsgs_default error\n");
}

static void usage(void)
{
    printf("\n\n"
            "usage:\n"
            "  meshd-nl80211 [-B] [-i<ifname>]\n\n");
}

static int event_handler(struct nl_msg *msg, void *arg)
{
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    uint8_t *pos;
    int i;

    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
            genlmsg_attrlen(gnlh, 0), NULL);

    switch (gnlh->cmd) {
        case NL80211_CMD_FRAME:
            if (tb[NL80211_ATTR_FRAME] && nla_len(tb[NL80211_ATTR_FRAME])) {
                pos = nla_data(tb[NL80211_ATTR_FRAME]);
                printf("----------\n");
                printf("frame hexdump: ");
                for (i=0; i<nla_len(tb[NL80211_ATTR_FRAME]); i++) {
                    if (!(i%20)) printf("\n");
                    printf("%02x ", *pos++);
                }
                printf("\n----------\n\n");
            }
            break;
        case NL80211_CMD_NEW_STATION:
            printf("NL80211_CMD_NEW_STATION :)\n");
            break;
        default:
            printf("Ignored event\n");
            break;
    }

    return NL_SKIP;
}

int join_mesh_rsn(char* ifname, char *mesh_id, int mesh_id_len)
{
    struct nl_msg *msg;
    uint8_t cmd = NL80211_CMD_JOIN_MESH;
    int ret;
    char *pret;
    char rsn_ie[0x14] = {0x30, /* RSN element ID */
                       0x12, /* length */
                       0x1, 0x0, /* Version */
                       0x0, 0x0F, 0xAC, 0x4, /* CCMP for group cipher suite */
                       0x1, 0x0,             /* pairwise suite count */
                       0x0, 0x0F, 0xAC, 0x4, /* CCMP for pairwise cipher suite */
                       0x1, 0x0,             /* authentication suite count */
                       0x0, 0x0F, 0xAC, 0x4, /* SAE for authentication */
                       /* optional capabilities omitted */
                       };

    int ifindex = if_nametoindex(ifname);

    assert(rsn_ie[1] = sizeof(rsn_ie) - 2);

    msg = nlmsg_alloc();
    if (!msg)
        return -ENOMEM;

    if (!mesh_id || !mesh_id_len)
        return -EINVAL;

    printf("meshd: Staring mesh with mesh id = %s\n", mesh_id);

    pret = genlmsg_put(msg, 0, 0,
            genl_family_get_id(nlcfg.nl80211), 0, 0, cmd, 0);
    if (pret == NULL)
        goto nla_put_failure;

    struct nlattr *container = nla_nest_start(msg,
            NL80211_ATTR_MESH_SETUP);

    if (!container)
        return -ENOBUFS;

    NLA_PUT(msg, NL80211_MESH_SETUP_RSN_IE, sizeof(rsn_ie), rsn_ie);
    nla_nest_end(msg, container);

    NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, ifindex);
    NLA_PUT(msg, NL80211_ATTR_MESH_ID, mesh_id_len, mesh_id);

    ret = send_and_recv(nlcfg.nl_sock, msg, NULL, NULL);
    if (ret)
        printf("Mesh start failed: %d (%s)\n", ret,
                strerror(-ret));
    else
        printf("Mesh start succeeded.  Yay!\n");

    return ret;
nla_put_failure:
    return -ENOBUFS;
}


int main(int argc, char *argv[])
{
    int c;
    int exitcode = 0;
    char *mesh_id;
    struct nl_sock *nlsock;

    for (;;) {
        c = getopt(argc, argv, "bi:s:");
        if (c < 0)
            break;
        switch (c) {
            case 'b':
                if (daemon(1, 0)) {
                    perror("daemon");
                    fprintf(stderr, "%s: unable to daemonize!\n",
                            argv[0]);
                    exit(1);
                }
                break;
            case 'i':
                ifname = optarg;
                break;
            case 's':
                mesh_id = optarg;
                break;
            default:
                usage();
                goto out;
        }
    }

    if (ifname == NULL) {
        usage();
        exitcode = -EINVAL;
        goto out;
    }

    if (netlink_init(&nlcfg, event_handler)) {
        exitcode = -ESOCKTNOSUPPORT;
        goto out;
    }

    if ((srvctx = srv_create_context()) == NULL) {
        fprintf(stderr, "%s: cannot create service context!\n",
                argv[0]);
        exitcode = -ENOMEM;
        goto out;
    }

    /* Add netlink sockets to our event loop */
    nlsock = nlcfg.nl_sock;
    srv_add_input(srvctx, nl_socket_get_fd(nlsock), nlsock,
            srv_handler_wrapper);
    nlsock = nlcfg.nl_sock_event;
    srv_add_input(srvctx, nl_socket_get_fd(nlsock), nlsock,
            srv_handler_wrapper);

    exitcode = join_mesh_rsn(ifname, mesh_id, strlen(mesh_id));
    if (exitcode)
        goto out;
    srv_main_loop(srvctx);
out:
    return exitcode;
}
