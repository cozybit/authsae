/*
 * Copyright (c) Dan Harkins, 2008, 2009, 2010;
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
#include <stdarg.h>
#include <signal.h>
#include <sys/select.h>
#include <stdlib.h>
#include <string.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <netinet/in.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/time.h>

#include "nlutils.h"

/* authsae headers */
#include "service.h"
#include "ieee802_11.h"
#include "sae.h"


/* Runtime config variables */
static char *ifname = NULL;
static struct netlink_config_s nlcfg;
service_context srvctx;

const char rsn_ie[0x14] = {0x30, /* RSN element ID */
                       0x12, /* length */
                       0x1, 0x0, /* Version */
                       0x0, 0x0F, 0xAC, 0x4, /* CCMP for group cipher suite */
                       0x1, 0x0,             /* pairwise suite count */
                       0x0, 0x0F, 0xAC, 0x4, /* CCMP for pairwise cipher suite */
                       0x1, 0x0,             /* authentication suite count */
                       0x0, 0x0F, 0xAC, 0x8, /* SAE for authentication */
                       /* optional capabilities omitted */
                       };

static void
debug_msg (const char *fmt, ...)
{
    va_list argptr;

    va_start(argptr, fmt);
    vfprintf(stderr, fmt, argptr);
    va_end(argptr);
}

int get_mac_addr(const char * ifname, uint8_t *macaddr)
{
    int fd;
    struct ifreq ifr;
    fd = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);

    if (ioctl(fd, SIOCGIFHWADDR, &ifr)) {
        debug_msg("meshd: failed to read mac address for %s\n", ifname);
        perror("meshd");
        return -1;
    }

    memcpy(macaddr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

    close(fd);

    return 0;
}


static const char * memmem(const char *haystack, int haystack_len, const char *needle, int needle_len)
{
    int hl, nl;
    for (hl = 0; hl<=haystack_len - needle_len; hl++) {
        for (nl = 0; nl<needle_len; nl++)
            if (haystack[hl+nl] != needle[nl])
                break;
        if (nl == needle_len)
            return &haystack[hl];
    }
    return NULL;
}

static void hexdump(const char *label, const char *start, int len)
{
    const char *pos;
    int i;
    struct timeval now;

    gettimeofday(&now, NULL);
    debug_msg("----------\n");
    debug_msg("%s hexdump: %d.%d", label, now.tv_sec, now.tv_usec);
    pos = start;
    for (i=0; i<len; i++) {
        if (!(i%20)) debug_msg("\n");
        debug_msg("%02x ", (unsigned char) *pos++);
    }
    debug_msg("\n----------\n\n");
    fflush(stdout);
    return;
}

static void srv_handler_wrapper(int fd, void *data)
{
    if (nl_recvmsgs_default((struct nl_sock *) data))
        fprintf(stderr, "nl_recvmsgs_default error\n");
    fflush(stdout);
}

static int tx_frame(struct netlink_config_s *nlcfg, char *frame, int len) {
    struct nl_msg *msg;
    uint8_t cmd = NL80211_CMD_FRAME;
    int ret = 0;
    char *pret;

    msg = nlmsg_alloc();
    if (!msg)
        return -ENOMEM;

    if (!frame || !len)
        return -EINVAL;

    pret = genlmsg_put(msg, 0, 0,
            genl_family_get_id(nlcfg->nl80211), 0, 0, cmd, 0);

    if (pret == NULL)
        goto nla_put_failure;

    NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, nlcfg->ifindex);
#define CHANNEL_1_FREQ  2412               /* XXX: obtain channel from interface */
    NLA_PUT_U32(msg, NL80211_ATTR_WIPHY_FREQ, CHANNEL_1_FREQ);
    NLA_PUT(msg, NL80211_ATTR_FRAME, len, frame);

    ret = send_nlmsg(nlcfg->nl_sock, msg);
    if (ret < 0)
        debug_msg("tx frame failed: %d (%s)\n", ret,
                strerror(-ret));
    else
        hexdump("tx frame", frame, len);
    return ret;
nla_put_failure:
    return -ENOBUFS;
}

int meshd_write_mgmt(char *buf, int len)
{
    tx_frame(&nlcfg, buf, len);
    return len;
}

void fin(int status, char *peer, char *buf, int len)
{
    debug_msg("fin: %d, key len:%d\n", status, len);
    if (!status)
        hexdump("pmk", buf, len % 80);
}


static int scan_results_handler(struct nl_msg *msg, void *arg)
{
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *bss[NL80211_BSS_MAX + 1];
    static struct nla_policy bss_policy[NL80211_BSS_MAX + 1] = {
        [NL80211_BSS_BSSID] = { .type = NLA_UNSPEC },
        [NL80211_BSS_FREQUENCY] = { .type = NLA_U32 },
        [NL80211_BSS_TSF] = { .type = NLA_U64 },
        [NL80211_BSS_BEACON_INTERVAL] = { .type = NLA_U16 },
        [NL80211_BSS_CAPABILITY] = { .type = NLA_U16 },
        [NL80211_BSS_INFORMATION_ELEMENTS] = { .type = NLA_UNSPEC },
        [NL80211_BSS_SIGNAL_MBM] = { .type = NLA_U32 },
        [NL80211_BSS_SIGNAL_UNSPEC] = { .type = NLA_U8 },
        [NL80211_BSS_STATUS] = { .type = NLA_U32 },
        [NL80211_BSS_SEEN_MS_AGO] = { .type = NLA_U32 },
        [NL80211_BSS_BEACON_IES] = { .type = NLA_UNSPEC },
    };
    const uint8_t *ie;
    size_t ie_len;
    struct ieee80211_mgmt_frame bcn;

    /* check that all the required info exists: source address
     * (arrives as bssid), meshid (TODO!), mesh config(TODO!) and RSN
     * */
    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
            genlmsg_attrlen(gnlh, 0), NULL);

    if (!tb[NL80211_ATTR_BSS])
        return NL_SKIP;

    if (nla_parse_nested(bss, NL80211_BSS_MAX, tb[NL80211_ATTR_BSS],
                bss_policy))
        return NL_SKIP;

    if (!bss[NL80211_BSS_BSSID])
        return NL_SKIP;

    if (!bss[NL80211_BSS_INFORMATION_ELEMENTS])
        return NL_SKIP;

    ie = nla_data(bss[NL80211_BSS_INFORMATION_ELEMENTS]);
    ie_len = nla_len(bss[NL80211_BSS_INFORMATION_ELEMENTS]);

	/* JC: For now, just do a brute search for the RSN ie in
	 * these scan results. When we move this to wpa_supplicant
	 * we'll use the available ie parsing routines
	 * */
    if (memmem((const char *) ie, ie_len, rsn_ie, sizeof(rsn_ie)) == NULL)
        return NL_SKIP;

    memset(&bcn, 0, sizeof(bcn));
    bcn.frame_control = htole16(
            (IEEE802_11_FC_TYPE_MGMT << 2 |
             IEEE802_11_FC_STYPE_BEACON << 4));
    memcpy(bcn.sa, nla_data(bss[NL80211_BSS_BSSID]), ETH_ALEN);

    if (process_mgmt_frame(&bcn, sizeof(bcn), nlcfg.mymacaddr))
        fprintf(stderr, "libsae: process_mgmt_frame failed\n");

    return NL_SKIP;
}

static int trigger_scan(struct netlink_config_s *nlcfg)
{
    struct nl_msg *msg, *freqs;
    uint8_t cmd = NL80211_CMD_TRIGGER_SCAN;
    int ret;
    char *pret;

    msg = nlmsg_alloc();
    freqs = nlmsg_alloc();

    if (!msg || !freqs)
        return -ENOMEM;

    pret = genlmsg_put(msg, 0, 0, genl_family_get_id(nlcfg->nl80211), 0, 0,
        cmd, 0);

    if (pret == NULL)
        goto nla_put_failure;

    NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, nlcfg->ifindex);
    NLA_PUT_U32(freqs, 1, CHANNEL_1_FREQ);
    nla_put_nested(msg, NL80211_ATTR_SCAN_FREQUENCIES, freqs);

    ret = send_nlmsg(nlcfg->nl_sock, msg);
    if (ret < 0)
        debug_msg("Scan failed: %d (%s)\n", ret,
                strerror(-ret));
    return ret;
nla_put_failure:
    return -ENOBUFS;
}

static int register_for_auth_frames(struct netlink_config_s *nlcfg)
{
        struct nl_msg *msg;
        uint8_t cmd = NL80211_CMD_REGISTER_FRAME;
#define IEEE80211_FTYPE_MGMT            0x0000
#define IEEE80211_STYPE_AUTH            0x00B0
        uint16_t frame_type = IEEE80211_FTYPE_MGMT | IEEE80211_STYPE_AUTH;
        int ret;
        char *pret;
        char auth_algo[1] = { 0x3};     /* SAE */

        msg = nlmsg_alloc();
        if (!msg)
                return -ENOMEM;

        pret = genlmsg_put(msg, 0, 0,
                genl_family_get_id(nlcfg->nl80211), 0, 0, cmd, 0);
        if (pret == NULL)
                goto nla_put_failure;

        NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, nlcfg->ifindex);
        NLA_PUT_U16(msg, NL80211_ATTR_FRAME_TYPE, frame_type);
        NLA_PUT(msg, NL80211_ATTR_FRAME_MATCH, sizeof(auth_algo), auth_algo);

        ret = send_nlmsg(nlcfg->nl_sock, msg);
        if (ret < 0)
                fprintf(stderr ,"Registering for auth frames failed: %d (%s)\n", ret,
                        strerror(-ret));
        else
            ret = 0;

        return ret;
 nla_put_failure:
        return -ENOBUFS;
}

static int request_scan_results(struct netlink_config_s *nlcfg)
{
    struct nl_msg *msg;
    uint8_t cmd = NL80211_CMD_GET_SCAN;
    int ret;
    char *pret;

    assert(nlcfg);

    msg = nlmsg_alloc();
    if (!msg)
        return -ENOMEM;

    pret = genlmsg_put(msg, 0, 0,
            genl_family_get_id(nlcfg->nl80211), 0, NLM_F_DUMP, cmd, 0);

    if (pret == NULL)
        goto nla_put_failure;

    NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, nlcfg->ifindex);

    ret = send_nlmsg(nlcfg->nl_sock, msg);
    if (ret < 0)
        debug_msg("Scan results request failed: %d (%s)\n", ret,
                strerror(-ret));
    return ret;
nla_put_failure:
    return -ENOBUFS;
}

static void srv_timeout_wrapper(timerid t, void *data)
{
    trigger_scan(data);
    srv_add_timeout(srvctx, SRV_SEC(10), srv_timeout_wrapper, data);
    return;
}

static void usage(void)
{
    debug_msg("\n\n"
            "usage:\n"
            "  meshd-nl80211 [-B] [-i<ifname>]\n\n");
}

static int event_handler(struct nl_msg *msg, void *arg)
{
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct ieee80211_mgmt_frame *frame;
    int frame_len;

    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
            genlmsg_attrlen(gnlh, 0), NULL);

    /* Ignore events for other interfaces */
    if (tb[NL80211_ATTR_IFINDEX] && nlcfg.ifindex != *(uint32_t *)nla_data(tb[NL80211_ATTR_IFINDEX]))
        return NL_SKIP;

    switch (gnlh->cmd) {
        case NL80211_CMD_FRAME:
            if (tb[NL80211_ATTR_FRAME] && nla_len(tb[NL80211_ATTR_FRAME])) {
                debug_msg("NL80211_CMD_FRAME\n");
                frame = nla_data(tb[NL80211_ATTR_FRAME]);
                frame_len = nla_len(tb[NL80211_ATTR_FRAME]);
                hexdump("rx frame", (char *)frame, frame_len);
                if (process_mgmt_frame(frame, frame_len, nlcfg.mymacaddr))
                    fprintf(stderr, "libsae: process_mgmt_frame failed\n");
            }
            break;
        case NL80211_CMD_NEW_STATION:
            debug_msg("NL80211_CMD_NEW_STATION\n");
            break;
        case NL80211_CMD_NEW_SCAN_RESULTS:
            debug_msg("NL80211_CMD_NEW_SCAN_RESULTS\n");
            if (tb[NL80211_ATTR_GENERATION])
                /* scan results received */
                return scan_results_handler(msg, arg);
            else
                /* scan done */
                request_scan_results(&nlcfg);
            break;
        case NL80211_CMD_TRIGGER_SCAN:
            debug_msg("NL80211_CMD_TRIGGER_SCAN\n");
            break;
        case NL80211_CMD_FRAME_TX_STATUS:
            debug_msg("NL80211_CMD_TX_STATUS\n");
            if (!tb[NL80211_ATTR_ACK] || !tb[NL80211_ATTR_FRAME])
                debug_msg("tx frame failed!");
            break;
        default:
            debug_msg("Ignored event (%d)\n", gnlh->cmd);
            break;
    }

    return NL_SKIP;
}

int join_mesh_rsn(struct netlink_config_s *nlcfg, char *mesh_id, int mesh_id_len)
{
    struct nl_msg *msg;
    uint8_t cmd = NL80211_CMD_JOIN_MESH;
    int ret;
    char *pret;

    assert(rsn_ie[1] == sizeof(rsn_ie) - 2);

    msg = nlmsg_alloc();
    if (!msg)
        return -ENOMEM;

    if (!mesh_id || !mesh_id_len)
        return -EINVAL;

    debug_msg("meshd: Staring mesh with mesh id = %s\n", mesh_id);

    pret = genlmsg_put(msg, 0, 0,
            genl_family_get_id(nlcfg->nl80211), 0, 0, cmd, 0);
    if (pret == NULL)
        goto nla_put_failure;

    struct nlattr *container = nla_nest_start(msg,
            NL80211_ATTR_MESH_CONFIG);

    if (!container)
        return -ENOBUFS;

    NLA_PUT_U32(msg, NL80211_MESHCONF_AUTO_OPEN_PLINKS, 0);
    nla_nest_end(msg, container);

    container = nla_nest_start(msg,
            NL80211_ATTR_MESH_SETUP);

    if (!container)
        return -ENOBUFS;

    NLA_PUT(msg, NL80211_MESH_SETUP_RSN_IE, sizeof(rsn_ie), rsn_ie);
    nla_nest_end(msg, container);

    NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, nlcfg->ifindex);
    NLA_PUT(msg, NL80211_ATTR_MESH_ID, mesh_id_len, mesh_id);

    ret = send_nlmsg(nlcfg->nl_sock, msg);
    if (ret < 0)
        fprintf(stderr,"Mesh start failed: %d (%s)\n", ret, strerror(-ret));
    else
        ret = 0;

    return ret;
nla_put_failure:
    return -ENOBUFS;
}

void term_handle(int i)
{
    exit(1);
}

int main(int argc, char *argv[])
{
    int c;
    int exitcode = 0;
    char *mesh_id;
    struct nl_sock *nlsock;
    int daemonize = 0;
    char *outfile = NULL;
    char confdir[80];

    signal(SIGTERM, term_handle);

    for (;;) {
        c = getopt(argc, argv, "I:o:Bi:s:");
        if (c < 0)
            break;
        switch (c) {
            case 'B':
                daemonize = 1;
                break;
            case 'o':
                outfile = optarg;
                break;
            case 'i':
                ifname = optarg;
                nlcfg.ifindex = if_nametoindex(ifname);
                break;
            case 's':
                mesh_id = optarg;
                break;
            case 'I':
                strncpy(confdir, optarg, sizeof(confdir));
                break;
            default:
                usage();
                goto out;
        }
    }

    if (ifname == NULL || confdir == NULL) {
        usage();
        exitcode = -EINVAL;
        goto out;
    }

    exitcode = get_mac_addr(ifname, nlcfg.mymacaddr);
    if (exitcode)
        goto out;

    if (sae_initialize(mesh_id, confdir) < 0) {
        fprintf(stderr, "%s: cannot configure SAE, check config file!\n", argv[0]);
        exit(1);
    }

    if (daemonize)
        daemon(1, 0);

    if (outfile)
        freopen(outfile, "w", stdout);

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

    exitcode = register_for_auth_frames(&nlcfg);
    if (exitcode)
        goto out;

    exitcode = join_mesh_rsn(&nlcfg, mesh_id, strlen(mesh_id));
    if (exitcode)
        goto out;

    /* periodically check for scan results to detect new neighbors */
    srv_add_timeout(srvctx, SRV_SEC(1), srv_timeout_wrapper, &nlcfg);

    srv_main_loop(srvctx);
out:
    return exitcode;
}
