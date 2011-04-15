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
#include "ampe.h"
#include "common.h"


/* Runtime config variables */
static char *ifname = NULL;
static struct netlink_config_s nlcfg;
service_context srvctx;

const char rsn_ie[0x16] = {0x30, /* RSN element ID */
                       0x14, /* length */
                       0x1, 0x0, /* Version */
                       0x0, 0x0F, 0xAC, 0x4, /* CCMP for group cipher suite */
                       0x1, 0x0,             /* pairwise suite count */
                       0x0, 0x0F, 0xAC, 0x4, /* CCMP for pairwise cipher suite */
                       0x1, 0x0,             /* authentication suite count */
                       0x0, 0x0F, 0xAC, 0x8, /* SAE for authentication */
                       0x0, 0x0,             /* Capabilities */
                       };

static int new_unauthenticated_peer(struct netlink_config_s *nlcfg, char *mac);

/* Undo libnl's error code translation.  See nl_syserr2nlerr */
static void nl2syserr(int error)
{
        error = abs(error);

        switch (error) {
        case NLE_BAD_SOCK:		fprintf(stderr, "EBADF or ENOTSOCK\n"); break;
        case NLE_EXIST:			fprintf(stderr, "EADDRINUSE or EEXIST\n"); break;
        case NLE_NOADDR:		fprintf(stderr, "EADDRNOTAVAIL\n"); break;
        case NLE_OBJ_NOTFOUND:	fprintf(stderr, "ENOENT\n"); break;
        case NLE_INTR:			fprintf(stderr, "EINTR\n"); break;
        case NLE_AGAIN:			fprintf(stderr, "EAGAIN\n"); break;
        case NLE_INVAL:			fprintf(stderr, "EINVAL, ENOPROTOOPT or EFAULT\n"); break;
        case NLE_NOACCESS:		fprintf(stderr, "EACCES\n"); break;
        case NLE_NOMEM:			fprintf(stderr, "ENOMEM or ENOBUFS\n"); break;
        case NLE_AF_NOSUPPORT:	fprintf(stderr, "EAFNOSUPPORT\n"); break;
        case NLE_PROTO_MISMATCH:fprintf(stderr, "EPROTONOSUPPORT\n"); break;
        case NLE_OPNOTSUPP:		fprintf(stderr, "EOPNOTSUPP\n"); break;
        case NLE_PERM:			fprintf(stderr, "EPERM\n"); break;
        case NLE_BUSY:			fprintf(stderr, "EBUSY\n"); break;
        case NLE_RANGE:			fprintf(stderr, "ERANGE\n"); break;
        default:                fprintf(stderr, "UNKNOWN NL ERROR\n"); break;
        }
        return;
}

int get_mac_addr(const char * ifname, uint8_t *macaddr)
{
    int fd;
    struct ifreq ifr;
    fd = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);

    if (ioctl(fd, SIOCGIFHWADDR, &ifr)) {
        sae_debug(MESHD_DEBUG, "meshd: failed to read mac address for %s\n", ifname);
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

static void srv_handler_wrapper(int fd, void *data)
{
    int err;
    if ((err = nl_recvmsgs_default((struct nl_sock *) data)) != 0) {
        fprintf(stderr, "srv_handler_wrapper(): nl_recvmsgs_default failed (nl error %d, errno %d)\n", err, errno);
        nl2syserr(err);
        perror("srv_handler_wrapper()\n");
    }
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
    NLA_PUT_U32(msg, NL80211_ATTR_WIPHY_FREQ, nlcfg->freq);
    NLA_PUT(msg, NL80211_ATTR_FRAME, len, frame);

    ret = send_nlmsg(nlcfg->nl_sock, msg);
    if (ret < 0)
        sae_debug(MESHD_DEBUG, "tx frame failed: %d (%s)\n", ret,
                strerror(-ret));
    else
        sae_hexdump(MESHD_DEBUG, "tx frame", frame, len);
    return ret;
nla_put_failure:
    return -ENOBUFS;
}

int meshd_write_mgmt(char *buf, int len)
{
    tx_frame(&nlcfg, buf, len);
    return len;
}

static int new_candidate_handler(struct nl_msg *msg, void *arg)
{
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    const uint8_t *ie;
    size_t ie_len;
    struct ieee80211_mgmt_frame bcn;

    /* check that all the required info exists: source address
     * (arrives as bssid), meshid (TODO!), mesh config(TODO!) and RSN
     * */
    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
            genlmsg_attrlen(gnlh, 0), NULL);

    if (!tb[NL80211_ATTR_MAC] || !tb[NL80211_ATTR_IE])
        return NL_SKIP;

    ie = nla_data(tb[NL80211_ATTR_IE]);
    ie_len = nla_len(tb[NL80211_ATTR_IE]);

	/* JC: For now, just do a brute search for the RSN ie in
	 * these scan results. When we move this to wpa_supplicant
	 * we'll use the available ie parsing routines
	 * */
    if (memmem((const char *) ie, ie_len, rsn_ie, sizeof(rsn_ie)) == NULL) {
        sae_hexdump(MESHD_DEBUG, "ie dump", (char *)ie, ie_len);
        return NL_SKIP;
    }

    memset(&bcn, 0, sizeof(bcn));
    bcn.frame_control = htole16(
            (IEEE802_11_FC_TYPE_MGMT << 2 |
             IEEE802_11_FC_STYPE_BEACON << 4));
    memcpy(bcn.sa, nla_data(tb[NL80211_ATTR_MAC]), ETH_ALEN);

    new_unauthenticated_peer(&nlcfg, (char *)bcn.sa);

    if (process_mgmt_frame(&bcn, sizeof(bcn), nlcfg.mymacaddr, NULL))
        fprintf(stderr, "libsae: process_mgmt_frame failed\n");


    return NL_SKIP;
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

    if (process_mgmt_frame(&bcn, sizeof(bcn), nlcfg.mymacaddr, NULL))
        fprintf(stderr, "libsae: process_mgmt_frame failed\n");

    return NL_SKIP;
}

static int register_for_plink_frames(struct netlink_config_s *nlcfg)
{
        struct nl_msg *msg;
        uint8_t cmd = NL80211_CMD_REGISTER_FRAME;
        int i;
#define IEEE80211_FTYPE_MGMT            0x0000
#define IEEE80211_STYPE_ACTION          0x00D0
        uint16_t frame_type = IEEE80211_FTYPE_MGMT | IEEE80211_STYPE_ACTION;
        int ret = 0;
        char *pret;
        char action_codes[3][2] = {{15, 1 }, {15, 2}, {15, 3}};  /* 11s draft 10.0, Table 7-24, Self-Protected */

        for (i = 0; i < 3; i++) {
            msg = nlmsg_alloc();
            if (!msg)
                    return -ENOMEM;

            pret = genlmsg_put(msg, 0, 0,
                    genl_family_get_id(nlcfg->nl80211), 0, 0, cmd, 0);
            if (pret == NULL)
                    goto nla_put_failure;

            NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, nlcfg->ifindex);
            NLA_PUT_U16(msg, NL80211_ATTR_FRAME_TYPE, frame_type);
            NLA_PUT(msg, NL80211_ATTR_FRAME_MATCH, sizeof(action_codes[i]), action_codes[i]);

            ret = send_nlmsg(nlcfg->nl_sock, msg);
            if (ret < 0)
                    fprintf(stderr ,"Registering for auth frames failed: %d (%s)\n", ret,
                            strerror(-ret));
            else
                ret = 0;
        }

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
        sae_debug(MESHD_DEBUG, "Scan results request failed: %d (%s)\n", ret,
                strerror(-ret));
    return ret;
nla_put_failure:
    return -ENOBUFS;
}

#if 0
static void srv_timeout_wrapper(timerid t, void *data)
{
    trigger_scan(data);
    srv_add_timeout(srvctx, SRV_SEC(60), srv_timeout_wrapper, data);
    return;
}
#endif

static void usage(void)
{
    sae_debug(MESHD_DEBUG, "\n\n"
            "usage:\n"
            "  meshd-nl80211 [-B] [-i<ifname>]\n\n");
}

static int event_handler(struct nl_msg *msg, void *arg)
{
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct ieee80211_mgmt_frame *frame;
    int frame_len;
    struct timeval now;

    gettimeofday(&now, NULL);

    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
            genlmsg_attrlen(gnlh, 0), NULL);

    /* Ignore events for other interfaces */
    if (tb[NL80211_ATTR_IFINDEX] && nlcfg.ifindex != *(uint32_t *)nla_data(tb[NL80211_ATTR_IFINDEX]))
        return NL_SKIP;

    switch (gnlh->cmd) {
        case NL80211_CMD_FRAME:
            if (tb[NL80211_ATTR_FRAME] && nla_len(tb[NL80211_ATTR_FRAME])) {
                sae_debug(MESHD_DEBUG, "NL80211_CMD_FRAME (%d.%d)\n", now.tv_sec, now.tv_usec);
                frame = nla_data(tb[NL80211_ATTR_FRAME]);
                frame_len = nla_len(tb[NL80211_ATTR_FRAME]);
                sae_hexdump(MESHD_DEBUG, "rx frame", (char *)frame, frame_len);
                /* Auth frames go to SAE */
                if (frame->frame_control == htole16((IEEE802_11_FC_TYPE_MGMT << 2 |
                                                      IEEE802_11_FC_STYPE_AUTH << 4))) {
                    if (process_mgmt_frame(frame, frame_len, nlcfg.mymacaddr, NULL))
                        fprintf(stderr, "libsae: process_mgmt_frame failed\n");
                /* Action (peer link) also go to SAE */
                } else if (frame->frame_control == htole16((IEEE802_11_FC_TYPE_MGMT << 2 |
                                                      IEEE802_11_FC_STYPE_ACTION << 4))) {
                    if (process_mgmt_frame(frame, frame_len, nlcfg.mymacaddr, NULL))
                        fprintf(stderr, "libsae: process_mgmt_frame failed\n");
                } else
                    sae_debug(MESHD_DEBUG, "got unexpected frame (%d.%d)\n", now.tv_sec, now.tv_usec);
            }
            break;
        case NL80211_CMD_NEW_STATION:
            sae_debug(MESHD_DEBUG, "NL80211_CMD_NEW_STATION (%d.%d)\n", now.tv_sec, now.tv_usec);
            break;
        case NL80211_CMD_NEW_PEER_CANDIDATE:
            sae_debug(MESHD_DEBUG, "NL80211_CMD_NEW_PEER_CANDIDATE(%d.%d)\n", now.tv_sec, now.tv_usec);
            new_candidate_handler(msg, arg);
            break;
        case NL80211_CMD_NEW_SCAN_RESULTS:
            sae_debug(MESHD_DEBUG, "NL80211_CMD_NEW_SCAN_RESULTS (%d.%d)\n", now.tv_sec, now.tv_usec);
            if (tb[NL80211_ATTR_GENERATION]) {
                sae_debug(MESHD_DEBUG, "retrieving results...\n");
                return scan_results_handler(msg, arg);
            } else {
                sae_debug(MESHD_DEBUG, "requesting results\n");
                request_scan_results(&nlcfg);
            }
            break;
        case NL80211_CMD_TRIGGER_SCAN:
            sae_debug(MESHD_DEBUG, "NL80211_CMD_TRIGGER_SCAN (%d.%d)\n", now.tv_sec, now.tv_usec);
            break;
        case NL80211_CMD_FRAME_TX_STATUS:
            sae_debug(MESHD_DEBUG, "NL80211_CMD_TX_STATUS (%d.%d)\n", now.tv_sec, now.tv_usec);
            if (!tb[NL80211_ATTR_ACK] || !tb[NL80211_ATTR_FRAME])
                sae_debug(MESHD_DEBUG, "tx frame failed!");
            break;
        default:
            sae_debug(MESHD_DEBUG, "Ignored event (%d)\n", gnlh->cmd);
            break;
    }

    return NL_SKIP;
}

int open_peer_link(struct netlink_config_s *nlcfg, char *peer)
{
    struct nl_msg *msg;
    uint8_t cmd = NL80211_CMD_SET_STATION;
    int ret;
    char *pret;

    if (!peer)
        return -EINVAL;

    msg = nlmsg_alloc();

    if (!msg)
        return -ENOMEM;

    pret = genlmsg_put(msg, 0, 0,
            genl_family_get_id(nlcfg->nl80211), 0, 0, cmd, 0);

    if (pret == NULL)
        goto nla_put_failure;

    NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, nlcfg->ifindex);
    NLA_PUT(msg, NL80211_ATTR_MAC, ETH_ALEN, peer);
#define    PLINK_ACTION_OPEN    1
    NLA_PUT_U8(msg, NL80211_ATTR_STA_PLINK_ACTION, PLINK_ACTION_OPEN);

    ret = send_nlmsg(nlcfg->nl_sock, msg);
    if (ret < 0)
        fprintf(stderr,"Peer link command failed: %d (%s)\n", ret, strerror(-ret));
    else
        ret = 0;

    return ret;
nla_put_failure:
    return -ENOBUFS;
}

static int set_authenticated_flag(struct netlink_config_s *nlcfg, char *peer)
{
    struct nl_msg *msg;
    uint8_t cmd = NL80211_CMD_SET_STATION;
    int ret;
    char *pret;
    struct nl80211_sta_flag_update flags;

    if (!peer)
        return -EINVAL;

    msg = nlmsg_alloc();

    if (!msg)
        return -ENOMEM;

    pret = genlmsg_put(msg, 0, 0,
            genl_family_get_id(nlcfg->nl80211), 0, 0, cmd, 0);

    if (pret == NULL)
        goto nla_put_failure;

    NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, nlcfg->ifindex);
    NLA_PUT(msg, NL80211_ATTR_MAC, ETH_ALEN, peer);
    flags.mask = flags.set = (1 << NL80211_STA_FLAG_AUTHENTICATED) |
                                (1 << NL80211_STA_FLAG_AUTHORIZED);

    NLA_PUT(msg, NL80211_ATTR_STA_FLAGS2, sizeof(flags), &flags);


    ret = send_nlmsg(nlcfg->nl_sock, msg);
    if (ret < 0)
        fprintf(stderr,"Failed to set auth flag on station: %d (%s)\n", ret, strerror(-ret));
    else
        ret = 0;

    return ret;
nla_put_failure:
    return -ENOBUFS;
}

static int set_plink_state(struct netlink_config_s *nlcfg, char *peer, int state)
{
    struct nl_msg *msg;
    uint8_t cmd = NL80211_CMD_SET_STATION;
    int ret;
    char *pret;

    if (!peer)
        return -EINVAL;

    msg = nlmsg_alloc();

    if (!msg)
        return -ENOMEM;

    pret = genlmsg_put(msg, 0, 0,
            genl_family_get_id(nlcfg->nl80211), 0, 0, cmd, 0);

    if (pret == NULL)
        goto nla_put_failure;

    NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, nlcfg->ifindex);
    NLA_PUT(msg, NL80211_ATTR_MAC, ETH_ALEN, peer);
    NLA_PUT_U8(msg, NL80211_ATTR_STA_PLINK_STATE, state);

    ret = send_nlmsg(nlcfg->nl_sock, msg);
    if (ret < 0)
        fprintf(stderr,"Peer link command failed: %d (%s)\n", ret, strerror(-ret));
    else
        ret = 0;

    return ret;
nla_put_failure:
    return -ENOBUFS;
}

static int new_unauthenticated_peer(struct netlink_config_s *nlcfg, char *peer)
{
    struct nl_msg *msg;
    uint8_t cmd = NL80211_CMD_NEW_STATION;
    int ret;
    char *pret;
    struct nl80211_sta_flag_update flags;
    uint8_t supported_rates[] = { 2, 4, 10, 22, 96, 108 };

    if (!peer)
        return -EINVAL;

    msg = nlmsg_alloc();

    if (!msg)
        return -ENOMEM;

    pret = genlmsg_put(msg, 0, 0,
            genl_family_get_id(nlcfg->nl80211), 0, 0, cmd, 0);

    if (pret == NULL)
        goto nla_put_failure;

    NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, nlcfg->ifindex);
    NLA_PUT(msg, NL80211_ATTR_MAC, ETH_ALEN, peer);
    NLA_PUT(msg, NL80211_ATTR_STA_SUPPORTED_RATES, sizeof(supported_rates),
            supported_rates);
    flags.mask = (1 << NL80211_STA_FLAG_AUTHENTICATED);
    flags.set = 0;

    NLA_PUT(msg, NL80211_ATTR_STA_FLAGS2, sizeof(flags), &flags);

    /* unused for mesh but mandatory for NL80211_CMD_NEW_STATION */
    NLA_PUT_U16(msg, NL80211_ATTR_STA_AID, 1);
    NLA_PUT_U16(msg, NL80211_ATTR_STA_LISTEN_INTERVAL, 100);

    ret = send_nlmsg(nlcfg->nl_sock, msg);
    if (ret < 0)
        fprintf(stderr,"New unauthenticated station failed: %d (%s)\n", ret, strerror(-ret));
    else
        ret = 0;

    return ret;
nla_put_failure:
    return -ENOBUFS;
}

int set_frequency(struct netlink_config_s *nlcfg, int freq)
{
    struct nl_msg *msg;
    uint8_t cmd = NL80211_CMD_SET_CHANNEL;
    int ret;
    char *pret;

    msg = nlmsg_alloc();
    if (!msg)
        return -ENOMEM;

    if (!freq)
        return -EINVAL;

    pret = genlmsg_put(msg, 0, 0,
            genl_family_get_id(nlcfg->nl80211), 0, 0, cmd, 0);
    if (pret == NULL)
        goto nla_put_failure;

    NLA_PUT_U32(msg, NL80211_ATTR_WIPHY_FREQ, freq);
    NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, nlcfg->ifindex);

    ret = send_nlmsg(nlcfg->nl_sock, msg);
    if (ret < 0)
        fprintf(stderr,"Set channel failed: %d (%s)\n", ret, strerror(-ret));
    else
        ret = 0;

    return ret;
nla_put_failure:
    return -ENOBUFS;
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

    sae_debug(MESHD_DEBUG, "meshd: Staring mesh with mesh id = %s\n", mesh_id);

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

    /* We'll be creating stations, not the kernel */
    NLA_PUT_FLAG(msg, NL80211_MESH_SETUP_USERSPACE_AUTH);

    /* We'll handle peer link frames */
    NLA_PUT_FLAG(msg, NL80211_MESH_SETUP_USERSPACE_AMPE);

    NLA_PUT(msg, NL80211_MESH_SETUP_IE, sizeof(rsn_ie), rsn_ie);
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

void estab_peer_link(unsigned char *peer)
{
    if (peer) {
        sae_debug(MESHD_DEBUG, "estab with " MACSTR "\n", MAC2STR(peer));
/* from include/net/cfg80211.h */
#define PLINK_ESTAB 4
        set_plink_state(&nlcfg, (char *)peer, PLINK_ESTAB);
    }
}

void fin(int status, char *peer, char *buf, int len)
{
    sae_debug(MESHD_DEBUG, "fin: %d, key len:%d\n", status, len);
    if (!status && len) {
        sae_hexdump(MESHD_DEBUG, "pmk", buf, len % 80);
        /* It may be that the kernel does not know about this station yet.
         * We could either check if it exists or just attempt to create
         * blindly and let it fail if it already exists.  Doing the latter.
         */
        //new_unauthenticated_peer(&nlcfg, peer);
        set_authenticated_flag(&nlcfg, peer);

        /* If auto peer link open is turned off  but we want the
         * kernel to run the peering protocol */
        //open_peer_link(&nlcfg, peer);
        /* Userspace initiates the peering */
        start_peer_link((unsigned char *) peer, (unsigned char *) nlcfg.mymacaddr, NULL);
    }
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
    struct sae_config config;

    signal(SIGTERM, term_handle);

    memset(&nlcfg, 0, sizeof(nlcfg));

    for (;;) {
        c = getopt(argc, argv, "I:o:Bi:s:f:");
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
            case 'f':
                nlcfg.freq = atoi(optarg);
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

    if (! nlcfg.freq)
        nlcfg.freq = 2412;      /* default to channel 1 */

    /* TODO: Check if ifname is of type mesh and if it's up.
     * For now this is assumed to be true.
     */

    exitcode = get_mac_addr(ifname, nlcfg.mymacaddr);
    if (exitcode)
        goto out;

    sae_parse_config(confdir, &config);
    if (sae_initialize(mesh_id, &config) < 0) {
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

    exitcode = register_for_plink_frames(&nlcfg);
    if (exitcode) {
        fprintf(stderr, "cannot register for plink frame!\n");
        goto out;
    }

    exitcode = join_mesh_rsn(&nlcfg, mesh_id, strlen(mesh_id));
    if (exitcode)
        goto out;

    /* periodically check for scan results to detect new neighbors */
    //srv_add_timeout(srvctx, SRV_SEC(600), srv_timeout_wrapper, &nlcfg);

    srv_main_loop(srvctx);
out:
    return exitcode;
}
