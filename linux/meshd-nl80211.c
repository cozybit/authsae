/* vim: et sw=4 ts=4
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

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <netlink/genl/genl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#if defined(__linux__) && !defined(__ANDROID__)
#ifdef __GLIBC__
#include <execinfo.h>
#endif
#endif /* defined(__linux__) && !defined(__ANDROID__) */

#include "ampe.h"
#include "common.h"
#include "nl80211-copy.h"
#include "nlutils.h"
#include "peers.h"
#include "rekey.h"
#include "sae.h"
#include "service.h"
#include "watch_ips.h"

#include <libconfig.h>

#define CIPHER_CCMP 0x000FAC04
#define CIPHER_AES_CMAC 0x000FAC06

/*  Notes on peer station lifecycle:
 *
 *  Stations in this context are either mesh neighbors, peer candidates or
 *  candidates.
 *
 *  Stations are created unauthenticated in the kernel when a
 *  NEW_PEER_CANDIDATE is received from the kernel.  Creating the
 *  unauthenticated station supresses further NEW_PEER_CANDIDATE (otherwise
 *  we would keep getting the event for every beacon received).
 *
 *  A sae invokes a meshd callback when a new station needs to be created.
 *  Failure to authenticate involves the destruction of a station.
 *
 *  Every station in the kernel exists also in userspace, in the 'peers' list
 *  maintained by sae.c and updated by ampe.c.
 *
 *  SAE determines when a station is authenticated, while AMPE determines
 *  the peering state of a station.
 *
 *  The kernel is informed of the authenticated and established plink state
 *  when AMPE completes, through the estab_peer_link() callback.
 */

static struct netlink_config_s nlcfg;
service_context srvctx;

/* Mesh group temporal key */
extern unsigned char mgtk_tx[16];

/* global configuration data */
static struct meshd_config meshd_conf;
static struct mesh_node mesh;

const char rsn_ie[0x16] = {
    0x30, /* RSN element ID */
    0x14, /* length */
    0x1,  0x0, /* Version */
    0x0,  0x0F, 0xAC, 0x4, /* CCMP for group cipher suite */
    0x1,  0x0, /* pairwise suite count */
    0x0,  0x0F, 0xAC, 0x4, /* CCMP for pairwise cipher suite */
    0x1,  0x0, /* authentication suite count */
    0x0,  0x0F, 0xAC, 0x8, /* SAE for authentication */
    0x0,  0x0, /* Capabilities */
};

/* Undo libnl's error code translation.  See nl_syserr2nlerr */
static void nl2syserr(int error) {
  error = abs(error);

  switch (error) {
    case NLE_BAD_SOCK:
      fprintf(stderr, "EBADF or ENOTSOCK\n");
      break;
    case NLE_EXIST:
      fprintf(stderr, "EADDRINUSE or EEXIST\n");
      break;
    case NLE_NOADDR:
      fprintf(stderr, "EADDRNOTAVAIL\n");
      break;
    case NLE_OBJ_NOTFOUND:
      fprintf(stderr, "ENOENT\n");
      break;
    case NLE_INTR:
      fprintf(stderr, "EINTR\n");
      break;
    case NLE_AGAIN:
      fprintf(stderr, "EAGAIN\n");
      break;
    case NLE_INVAL:
      fprintf(stderr, "EINVAL, ENOPROTOOPT or EFAULT\n");
      break;
    case NLE_NOACCESS:
      fprintf(stderr, "EACCES\n");
      break;
    case NLE_NOMEM:
      fprintf(stderr, "ENOMEM or ENOBUFS\n");
      break;
    case NLE_AF_NOSUPPORT:
      fprintf(stderr, "EAFNOSUPPORT\n");
      break;
    case NLE_PROTO_MISMATCH:
      fprintf(stderr, "EPROTONOSUPPORT\n");
      break;
    case NLE_OPNOTSUPP:
      fprintf(stderr, "EOPNOTSUPP\n");
      break;
    case NLE_PERM:
      fprintf(stderr, "EPERM\n");
      break;
    case NLE_BUSY:
      fprintf(stderr, "EBUSY\n");
      break;
    case NLE_RANGE:
      fprintf(stderr, "ERANGE\n");
      break;
    default:
      fprintf(stderr, "UNKNOWN NL ERROR\n");
      break;
  }
  return;
}

/* copy the phy supported rate set into the mesh conf, and hardcode
 * BSSBasicRateSet
 * as the mandatory phy rates for now */
/* TODO: allow user to configure BSSBasicRateSet */
static void
set_sup_basic_rates(struct meshd_config *mconf, u16 *rates, int rates_len) {
  int i, want;
  char basic = 0x80;

  memset(mconf->rates, 0, sizeof(mconf->rates));
  assert(sizeof(mconf->rates) >= rates_len);

  for (i = 0; i < rates_len; i++)
    /* nl80211 reports in 100kb/s, IEEE 802.11 is 500kb/s */
    mconf->rates[i] = (uint8_t)(rates[i] / 5);

  switch (mconf->band) {
    case MESHD_11a:
      want = 3;
      for (i = 0; i < rates_len; i++) {
        if (rates[i] == 60 || rates[i] == 120 || rates[i] == 240) {
          mconf->rates[i] |= basic;
          want--;
        }
      }
      assert(!want);
      break;
    case MESHD_11b:
    case MESHD_11g:
      want = 7;
      for (i = 0; i < rates_len; i++) {
        if (rates[i] == 10) {
          mconf->rates[i] |= basic;
          want--;
        }

        if (rates[i] == 20 || rates[i] == 55 || rates[i] == 110 ||
            rates[i] == 60 || rates[i] == 120 || rates[i] == 240) {
          mconf->rates[i] |= basic;
          want--;
        }
      }
      assert(want == 0 || want == 3 || want == 6);
      break;
  }
}

static enum ht_channel_type ht_op_to_channel_type(struct ht_op_ie *ht_op) {
  enum nl80211_channel_type channel_type;

  if (!ht_op)
    return CHAN_NO_HT;

  switch (ht_op->ht_param & IEEE80211_HT_PARAM_CHA_SEC_OFFSET) {
    case IEEE80211_HT_PARAM_CHA_SEC_NONE:
      channel_type = CHAN_HT20;
      break;
    case IEEE80211_HT_PARAM_CHA_SEC_ABOVE:
      channel_type = CHAN_HT40PLUS;
      break;
    case IEEE80211_HT_PARAM_CHA_SEC_BELOW:
      channel_type = CHAN_HT40MINUS;
      break;
    default:
      channel_type = CHAN_NO_HT;
      break;
  }

  return channel_type;
}

static int get_mac_addr(const char *ifname, uint8_t *macaddr) {
  int fd;
  struct ifreq ifr;
  fd = socket(AF_INET, SOCK_DGRAM, 0);

  ifr.ifr_addr.sa_family = AF_INET;
  strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

  if (ioctl(fd, SIOCGIFHWADDR, &ifr)) {
    sae_debug(
        SAE_DEBUG_ERR,
        "meshd: failed to read MAC address for interface \"%s\": %s\n",
        ifname,
        strerror(errno));
    return -1;
  }

  memcpy(macaddr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
  close(fd);

  return 0;
}

static void srv_handler_wrapper(int fd, void *data) {
  int err;
  if ((err = nl_recvmsgs_default((struct nl_sock *)data)) != 0) {
    nl2syserr(err);
  }
  fflush(stdout);
}

static int tx_frame(
    struct netlink_config_s *nlcfg,
    struct mesh_node *mesh,
    unsigned char *frame,
    int len) {
  struct nl_msg *msg;
  uint8_t cmd = NL80211_CMD_FRAME;
  int ret = 0;
  char *pret;

  sae_debug(MESHD_DEBUG, "%s(%p, %p, %d)\n", __FUNCTION__, nlcfg, frame, len);
  msg = nlmsg_alloc();
  if (!msg)
    return -ENOMEM;

  if (!frame || !len)
    return -EINVAL;

  pret = genlmsg_put(
      msg, 0, NL_AUTO_SEQ, genl_family_get_id(nlcfg->nl80211), 0, 0, cmd, 0);

  if (pret == NULL)
    goto nla_put_failure;

  NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, nlcfg->ifindex);
  NLA_PUT_U32(msg, NL80211_ATTR_WIPHY_FREQ, mesh->freq);
  NLA_PUT(msg, NL80211_ATTR_FRAME, len, frame);

  ret = send_nlmsg(nlcfg->nl_sock, msg);
  sae_debug(MESHD_DEBUG, "tx frame (seq num=%d)\n", nlmsg_hdr(msg)->nlmsg_seq);
  nlmsg_free(msg);
  msg = NULL;
  if (ret < 0)
    sae_debug(MESHD_DEBUG, "tx frame failed: %d (%s)\n", ret, strerror(-ret));
  else
    sae_hexdump(MESHD_DEBUG, "tx frame", frame, len);
  return ret;
nla_put_failure:
  nlmsg_free(msg);
  msg = NULL;
  return -ENOBUFS;
}

int meshd_write_mgmt(char *buf, int framelen, void *cookie) {
  tx_frame(&nlcfg, &mesh, (unsigned char *)buf, framelen);
  return framelen;
}

static int set_mesh_conf(
    struct netlink_config_s *nlcfg,
    struct mesh_node *mesh,
    uint32_t changed) {
  struct nl_msg *msg;
  uint8_t cmd = NL80211_CMD_SET_MESH_CONFIG;
  int ret = 0;
  char *pret;

  sae_debug(MESHD_DEBUG, "%s(%p, %d)\n", __FUNCTION__, nlcfg, changed);
  msg = nlmsg_alloc();
  if (!msg)
    return -ENOMEM;

  pret = genlmsg_put(
      msg, 0, NL_AUTO_SEQ, genl_family_get_id(nlcfg->nl80211), 0, 0, cmd, 0);

  if (pret == NULL)
    goto nla_put_failure;

  struct nlattr *container = nla_nest_start(msg, NL80211_ATTR_MESH_CONFIG);

  if (!container)
    goto nla_put_failure;

  if (changed & MESH_CONF_CHANGED_HT)
    NLA_PUT_U16(msg, NL80211_MESHCONF_HT_OPMODE, mesh->conf->ht_prot_mode);
  nla_nest_end(msg, container);

  NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, nlcfg->ifindex);

  ret = send_nlmsg(nlcfg->nl_sock, msg);
  sae_debug(
      MESHD_DEBUG, "set meshconf (seq num=%d)\n", nlmsg_hdr(msg)->nlmsg_seq);
  nlmsg_free(msg);
  msg = NULL;
  if (ret < 0)
    sae_debug(
        MESHD_DEBUG, "set meshconf failed: %d (%s)\n", ret, strerror(-ret));
  return ret;
nla_put_failure:
  nlmsg_free(msg);
  msg = NULL;
  return -ENOBUFS;
}

int meshd_set_mesh_conf(struct mesh_node *mesh, uint32_t changed) {
  return set_mesh_conf(&nlcfg, mesh, changed);
}

static void delete_peer_by_addr(unsigned char *addr) {
  struct candidate *peer;
  if ((peer = find_peer(addr, 0)))
    delete_peer(&peer);
}

static int
handle_del_peer(struct netlink_config_s *nlcfg, struct nl_msg *msg, void *arg) {
  struct nlattr *tb[NL80211_ATTR_MAX + 1];
  struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));

  nla_parse(
      tb,
      NL80211_ATTR_MAX,
      genlmsg_attrdata(gnlh, 0),
      genlmsg_attrlen(gnlh, 0),
      NULL);

  if (nla_get_u32(tb[NL80211_ATTR_IFINDEX]) != nlcfg->ifindex)
    return -1;

  if (!tb[NL80211_ATTR_MAC] || nla_len(tb[NL80211_ATTR_MAC]) != ETH_ALEN)
    return -1;

  ampe_close_peer_link(nla_data(tb[NL80211_ATTR_MAC]));
  delete_peer_by_addr(nla_data(tb[NL80211_ATTR_MAC]));

  return 0;
}

static int handle_wiphy(struct mesh_node *mesh, struct nl_msg *msg, void *arg) {
  struct nlattr *tb[NL80211_ATTR_MAX + 1];
  struct nlattr *tb_band[NL80211_BAND_ATTR_MAX + 1];
  struct nlattr *nl_band, *nl_rate;
  struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
  struct ieee80211_supported_band *lband;
  int rem_band, rem_rate, n_rates = 0;
  enum ieee80211_band band;
  uint16_t sup_rates[MAX_SUPP_RATES] = {0};
  struct nlattr *tb_rate[NL80211_BITRATE_ATTR_MAX + 1];
  static struct nla_policy rate_policy[NL80211_BITRATE_ATTR_MAX + 1] = {
          [NL80211_BITRATE_ATTR_RATE] = {.type = NLA_U32},
          [NL80211_BITRATE_ATTR_2GHZ_SHORTPREAMBLE] = {.type = NLA_FLAG},
  };

  nla_parse(
      tb,
      NL80211_ATTR_MAX,
      genlmsg_attrdata(gnlh, 0),
      genlmsg_attrlen(gnlh, 0),
      NULL);

  if (!tb[NL80211_ATTR_WIPHY_BANDS])
    return -1;

  nla_for_each_nested(nl_band, tb[NL80211_ATTR_WIPHY_BANDS], rem_band) {
    band = nl_band->nla_type;
    lband = &mesh->bands[band];

    nla_parse(
        tb_band,
        NL80211_BAND_ATTR_MAX,
        nla_data(nl_band),
        nla_len(nl_band),
        NULL);

    if (tb_band[NL80211_BAND_ATTR_HT_MCS_SET]) {
      assert(
          sizeof(lband->ht_cap.mcs) ==
          nla_len(tb_band[NL80211_BAND_ATTR_HT_MCS_SET]));
      lband->ht_cap.ht_supported = true;
      memcpy(
          &lband->ht_cap.mcs,
          nla_data(tb_band[NL80211_BAND_ATTR_HT_MCS_SET]),
          nla_len(tb_band[NL80211_BAND_ATTR_HT_MCS_SET]));
      lband->ht_cap.cap = nla_get_u16(tb_band[NL80211_BAND_ATTR_HT_CAPA]);
      lband->ht_cap.ampdu_factor =
          nla_get_u8(tb_band[NL80211_BAND_ATTR_HT_AMPDU_FACTOR]);
      lband->ht_cap.ampdu_density =
          nla_get_u8(tb_band[NL80211_BAND_ATTR_HT_AMPDU_DENSITY]);
    }

    n_rates = 0;
    nla_for_each_nested(nl_rate, tb_band[NL80211_BAND_ATTR_RATES], rem_rate) {
      nla_parse(
          tb_rate,
          NL80211_BITRATE_ATTR_MAX,
          nla_data(nl_rate),
          nla_len(nl_rate),
          rate_policy);
      if (!tb_rate[NL80211_BITRATE_ATTR_RATE])
        continue;
      sup_rates[n_rates] = nla_get_u32(tb_rate[NL80211_BITRATE_ATTR_RATE]);
      n_rates++;
    }

    if (n_rates) {
      lband->rates = malloc(n_rates * 2); // lband->rates is 16bit
      if (!lband->rates)
        return -ENOMEM;
      memcpy(lband->rates, sup_rates, n_rates * 2);
      lband->n_bitrates = n_rates;
    }
  }
  return 0;
}

static int add_unauthenticated_sta(
    struct netlink_config_s *nlcfg,
    unsigned char *peer,
    struct info_elems *elems) {
  struct nl_msg *msg;
  uint8_t cmd = NL80211_CMD_NEW_STATION;
  int ret;
  char *pret;
  struct nl80211_sta_flag_update flags;

  if (!peer)
    return -EINVAL;

  msg = nlmsg_alloc();

  if (!msg)
    return -ENOMEM;

  pret =
      genlmsg_put(msg, 0, 0, genl_family_get_id(nlcfg->nl80211), 0, 0, cmd, 0);

  if (pret == NULL)
    goto nla_put_failure;

  NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, nlcfg->ifindex);
  NLA_PUT(msg, NL80211_ATTR_MAC, ETH_ALEN, peer);

  if (elems->sup_rates) {
    NLA_PUT(
        msg,
        NL80211_ATTR_STA_SUPPORTED_RATES,
        elems->sup_rates_len,
        elems->sup_rates);
  }

  flags.mask =
      (1 << NL80211_STA_FLAG_AUTHENTICATED) | (1 << NL80211_STA_FLAG_WME);
  flags.set = (1 << NL80211_STA_FLAG_WME);

  NLA_PUT(msg, NL80211_ATTR_STA_FLAGS2, sizeof(flags), &flags);

  uint16_t peer_aid = find_peer(peer, /* accept */ 0)->association_id;
  NLA_PUT_U16(msg, NL80211_ATTR_STA_AID, peer_aid);

  NLA_PUT_U16(msg, NL80211_ATTR_STA_LISTEN_INTERVAL, 100);

  /* unset 20/40mhz in ht_cap if ht op ie indicates this is a 20mhz STA */
  if (elems->ht_info &&
      !(((struct ht_op_ie *)elems->ht_info)->ht_param &
        IEEE80211_HT_PARAM_CHAN_WIDTH_ANY))
    ((struct ht_cap_ie *)elems->ht_cap)->cap_info &=
        ~IEEE80211_HT_CAP_SUP_WIDTH_20_40;

  if (elems->ht_cap)
    NLA_PUT(msg, NL80211_ATTR_HT_CAPABILITY, elems->ht_cap_len, elems->ht_cap);

  ret = send_nlmsg(nlcfg->nl_sock, msg);
  sae_debug(
      MESHD_DEBUG,
      "new unauthed sta (seq num=%d)\n",
      nlmsg_hdr(msg)->nlmsg_seq);
  nlmsg_free(msg);
  msg = NULL;
  if (ret < 0)
    fprintf(stderr, "add station failed: %d (%s)\n", ret, strerror(-ret));
  else
    ret = 0;

  return ret;
nla_put_failure:
  nlmsg_free(msg);
  msg = NULL;
  return -ENOBUFS;
}

static int new_candidate_handler(struct nl_msg *msg, void *arg) {
  struct nlattr *tb[NL80211_ATTR_MAX + 1];
  struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
  unsigned char *ie;
  size_t ie_len;
  struct ieee80211_mgmt_frame bcn;
  struct info_elems elems;
  struct candidate *peer;

  /* check that all the required info exists: source address
   * (arrives as bssid), meshid, mesh config(TODO!) and RSN
   * */
  nla_parse(
      tb,
      NL80211_ATTR_MAX,
      genlmsg_attrdata(gnlh, 0),
      genlmsg_attrlen(gnlh, 0),
      NULL);

  if (!tb[NL80211_ATTR_MAC] || !tb[NL80211_ATTR_IE])
    return NL_SKIP;

  ie = nla_data(tb[NL80211_ATTR_IE]);
  ie_len = nla_len(tb[NL80211_ATTR_IE]);

  parse_ies(ie, ie_len, &elems);

  if (elems.mesh_id == NULL || elems.mesh_id_len != meshd_conf.meshid_len ||
      memcmp(elems.mesh_id, meshd_conf.meshid, meshd_conf.meshid_len) != 0) {
    sae_debug(MESHD_DEBUG, "Candidate from different Mesh ID\n");
    return NL_SKIP;
  }

  if (!elems.rsn && meshd_conf.is_secure) {
    sae_debug(MESHD_DEBUG, "No RSN IE from this candidate\n");
    return NL_SKIP;
  }

  memset(&bcn, 0, sizeof(bcn));
  bcn.frame_control =
      htole16((IEEE802_11_FC_TYPE_MGMT << 2 | IEEE802_11_FC_STYPE_BEACON << 4));
  memcpy(bcn.sa, nla_data(tb[NL80211_ATTR_MAC]), ETH_ALEN);

  if (process_mgmt_frame(
          &bcn, sizeof(bcn), mesh.mymacaddr, &nlcfg, !meshd_conf.is_secure) !=
      0) {
    fprintf(stderr, "libsae: process_mgmt_frame failed\n");
    return NL_SKIP;
  }

  /* if peer now exists, we know it was created by process_mgmt_frame, or if
   * we received two NEW_PEER_CANDIDATE events for the same peer, this will fail
   */
  if ((peer = find_peer(bcn.sa, 0))) {
    peer->ch_type = ht_op_to_channel_type((struct ht_op_ie *)elems.ht_info);
    if (!peer->in_kernel &&
        add_unauthenticated_sta(&nlcfg, bcn.sa, &elems) == 0) {
      peer->in_kernel = true;
    }
  }

  return NL_SKIP;
}

static int register_for_plink_frames(struct netlink_config_s *nlcfg) {
  struct nl_msg *msg;
  uint8_t cmd = NL80211_CMD_REGISTER_FRAME;
  int i;
#define IEEE80211_FTYPE_MGMT 0x0000
#define IEEE80211_STYPE_ACTION 0x00D0
  uint16_t frame_type = IEEE80211_FTYPE_MGMT | IEEE80211_STYPE_ACTION;
  int ret = 0;
  char *pret;
  char action_codes[3][2] = {
      {15, 1},
      {15, 2},
      {15, 3}}; /* 11s draft 10.0, Table 7-24, Self-Protected */

  for (i = 0; i < 3; i++) {
    msg = nlmsg_alloc();
    if (!msg)
      return -ENOMEM;

    pret = genlmsg_put(
        msg, 0, 0, genl_family_get_id(nlcfg->nl80211), 0, 0, cmd, 0);
    if (pret == NULL)
      goto nla_put_failure;

    NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, nlcfg->ifindex);
    NLA_PUT_U16(msg, NL80211_ATTR_FRAME_TYPE, frame_type);
    NLA_PUT(
        msg,
        NL80211_ATTR_FRAME_MATCH,
        sizeof(action_codes[i]),
        action_codes[i]);

    ret = send_nlmsg(nlcfg->nl_sock, msg);
    nlmsg_free(msg);
    msg = NULL;
    if (ret < 0)
      fprintf(
          stderr,
          "Registering for auth frames failed: %d (%s)\n",
          ret,
          strerror(-ret));
    else
      ret = 0;
  }

  return ret;
nla_put_failure:
  nlmsg_free(msg);
  msg = NULL;
  return -ENOBUFS;
}

static int register_for_auth_frames(struct netlink_config_s *nlcfg) {
  struct nl_msg *msg;
  uint8_t cmd = NL80211_CMD_REGISTER_FRAME;
#define IEEE80211_FTYPE_MGMT 0x0000
#define IEEE80211_STYPE_AUTH 0x00B0
  uint16_t frame_type = IEEE80211_FTYPE_MGMT | IEEE80211_STYPE_AUTH;
  int ret;
  char *pret;
  char auth_algo[1] = {0x3}; /* SAE */

  msg = nlmsg_alloc();
  if (!msg)
    return -ENOMEM;

  pret =
      genlmsg_put(msg, 0, 0, genl_family_get_id(nlcfg->nl80211), 0, 0, cmd, 0);
  if (pret == NULL)
    goto nla_put_failure;

  NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, nlcfg->ifindex);
  NLA_PUT_U16(msg, NL80211_ATTR_FRAME_TYPE, frame_type);
  NLA_PUT(msg, NL80211_ATTR_FRAME_MATCH, sizeof(auth_algo), auth_algo);

  ret = send_nlmsg(nlcfg->nl_sock, msg);
  nlmsg_free(msg);
  msg = NULL;
  if (ret < 0)
    fprintf(
        stderr,
        "Registering for auth frames failed: %d (%s)\n",
        ret,
        strerror(-ret));
  else
    ret = 0;

  return ret;
nla_put_failure:
  nlmsg_free(msg);
  msg = NULL;
  return -ENOBUFS;
}

static int get_wiphy(struct netlink_config_s *nlcfg) {
  struct nl_msg *msg;
  uint8_t cmd = NL80211_CMD_GET_WIPHY;
  int ret;
  char *pret;

  assert(nlcfg);

  msg = nlmsg_alloc();
  if (!msg)
    return -ENOMEM;

  pret = genlmsg_put(
      msg, 0, 0, genl_family_get_id(nlcfg->nl80211), 0, NLM_F_REQUEST, cmd, 0);

  if (pret == NULL)
    goto nla_put_failure;

  NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, nlcfg->ifindex);

  ret = send_nlmsg(nlcfg->nl_sock, msg);
  nlmsg_free(msg);
  msg = NULL;
  if (ret < 0)
    sae_debug(MESHD_DEBUG, "get wiphy failed: %d (%s)\n", ret, strerror(-ret));
  return ret;
nla_put_failure:
  nlmsg_free(msg);
  msg = NULL;
  return -ENOBUFS;
}

static int install_key(
    struct netlink_config_s *nlcfg,
    unsigned char *peer,
    unsigned int cipher,
    unsigned int keytype,
    unsigned char keyidx,
    unsigned char *keydata) {
  struct nl_msg *msg, *key = NULL;
  uint8_t cmd = NL80211_CMD_NEW_KEY;
  int ret;
  char *pret;
  unsigned char seq[6] = {0};

  assert(nlcfg);

  msg = nlmsg_alloc();
  if (!msg)
    return -ENOMEM;

  key = nlmsg_alloc();
  if (!key)
    goto nla_put_failure;

  pret =
      genlmsg_put(msg, 0, 0, genl_family_get_id(nlcfg->nl80211), 0, 0, cmd, 0);

  if (pret == NULL)
    goto nla_put_failure;

  NLA_PUT_U32(key, NL80211_KEY_CIPHER, cipher);
  NLA_PUT(key, NL80211_KEY_DATA, 16, keydata);
  NLA_PUT_U8(key, NL80211_KEY_IDX, keyidx);
  NLA_PUT(key, NL80211_KEY_SEQ, 6, seq);
  NLA_PUT_U32(key, NL80211_KEY_TYPE, keytype);
  ret = nla_put_nested(msg, NL80211_ATTR_KEY, key);
  if (ret)
    goto nla_put_failure;

  nlmsg_free(key);
  key = NULL;

  NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, nlcfg->ifindex);
  if (peer)
    NLA_PUT(msg, NL80211_ATTR_MAC, ETH_ALEN, peer);

  ret = send_nlmsg(nlcfg->nl_sock, msg);
  nlmsg_free(msg);
  msg = NULL;
  if (ret < 0)
    sae_debug(
        MESHD_DEBUG,
        "install mesh keys failed: %d (%s)\n",
        ret,
        strerror(-ret));

  if (peer)
    return 0;

  msg = nlmsg_alloc();
  if (!msg)
    return -ENOMEM;

  cmd = NL80211_CMD_SET_KEY;

  pret =
      genlmsg_put(msg, 0, 0, genl_family_get_id(nlcfg->nl80211), 0, 0, cmd, 0);

  if (pret == NULL)
    goto nla_put_failure;

  if (cipher == CIPHER_AES_CMAC)
    NLA_PUT_FLAG(msg, NL80211_ATTR_KEY_DEFAULT_MGMT);
  else
    NLA_PUT_FLAG(msg, NL80211_ATTR_KEY_DEFAULT);

  NLA_PUT_U8(msg, NL80211_ATTR_KEY_IDX, keyidx);
  NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, nlcfg->ifindex);
  ret = send_nlmsg(nlcfg->nl_sock, msg);
  nlmsg_free(msg);
  msg = NULL;
  if (ret < 0)
    sae_debug(
        MESHD_DEBUG,
        "install mesh keys failed: %d (%s)\n",
        ret,
        strerror(-ret));
  return ret;
nla_put_failure:
  nlmsg_free(key);
  nlmsg_free(msg);
  key = NULL;
  msg = NULL;
  return -ENOBUFS;
}

static void usage(void) {
  sae_debug(
      SAE_DEBUG_ERR,
      "\n\n"
      "usage: meshd-nl80211 [options]\n\n"
      "    -h               print this message\n"
      "    -c <conffile>    configuration file (see authsae.sample.conf for "
      "example)\n"
      "    -o <outfile>     output log file\n"
      "    -B               run in the background (i.e., daemonize)\n"
      "    -i <interface>   override interface value in config file\n"
      "    -s <meshid>      override mesh id provided in config file\n"
      "\n");
}

static int init(struct netlink_config_s *nlcfg, struct mesh_node *mesh);

static int event_handler(struct nl_msg *msg, void *arg) {
  struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
  struct nlattr *tb[NL80211_ATTR_MAX + 1];
  struct ieee80211_mgmt_frame *frame;
  int frame_len;
  unsigned short frame_control;
  struct timeval now;

  gettimeofday(&now, NULL);

  nla_parse(
      tb,
      NL80211_ATTR_MAX,
      genlmsg_attrdata(gnlh, 0),
      genlmsg_attrlen(gnlh, 0),
      NULL);

  /* Ignore events for other interfaces */
  if (tb[NL80211_ATTR_IFINDEX] &&
      nlcfg.ifindex != *(uint32_t *)nla_data(tb[NL80211_ATTR_IFINDEX]))
    return NL_SKIP;

  switch (gnlh->cmd) {
    /* test */
    case NL80211_CMD_NEW_WIPHY:
      assert(tb[NL80211_ATTR_SUPPORT_MESH_AUTH]);
      if (handle_wiphy(&mesh, msg, arg))
        sae_debug(MESHD_DEBUG, "error getting wiphy info! \n");
      /* wiphy handled, we are now ready start the mesh */
      init(&nlcfg, &mesh);
      break;
    case NL80211_CMD_DEL_STATION:
      handle_del_peer(&nlcfg, msg, arg);
      break;
    case NL80211_CMD_FRAME:
      if (tb[NL80211_ATTR_FRAME] && nla_len(tb[NL80211_ATTR_FRAME])) {
        sae_debug(
            MESHD_DEBUG,
            "NL80211_CMD_FRAME (%lld.%ld)\n",
            (long long)now.tv_sec,
            (long)now.tv_usec);
        frame = nla_data(tb[NL80211_ATTR_FRAME]);
        frame_len = nla_len(tb[NL80211_ATTR_FRAME]);
        frame_control = ieee_order(frame->frame_control);
        sae_hexdump(MESHD_DEBUG, "rx frame", (unsigned char *)frame, frame_len);
        /* Auth frames go to SAE */
        if (IEEE802_11_FC_GET_TYPE(frame_control) == IEEE802_11_FC_TYPE_MGMT &&
            (IEEE802_11_FC_GET_STYPE(frame_control) ==
                 IEEE802_11_FC_STYPE_ACTION ||
             IEEE802_11_FC_GET_STYPE(frame_control) ==
                 IEEE802_11_FC_STYPE_AUTH)) {
          if (process_mgmt_frame(
                  frame,
                  frame_len,
                  mesh.mymacaddr,
                  &nlcfg,
                  !meshd_conf.is_secure))
            fprintf(stderr, "libsae: process_mgmt_frame failed\n");
        } else
          sae_debug(
              MESHD_DEBUG,
              "got unexpected frame (%lld.%ld)\n",
              (long long)now.tv_sec,
              (long)now.tv_usec);
      }
      break;
    case NL80211_CMD_NEW_STATION:
      sae_debug(
          MESHD_DEBUG,
          "NL80211_CMD_NEW_STATION (%lld.%ld)\n",
          (long long)now.tv_sec,
          (long)now.tv_usec);
      break;
    case NL80211_CMD_NEW_PEER_CANDIDATE:
      sae_debug(
          MESHD_DEBUG,
          "NL80211_CMD_NEW_PEER_CANDIDATE(%lld.%ld)\n",
          (long long)now.tv_sec,
          (long)now.tv_usec);
      new_candidate_handler(msg, arg);
      break;
    case NL80211_CMD_FRAME_TX_STATUS:
      sae_debug(
          MESHD_DEBUG,
          "NL80211_CMD_TX_STATUS (%lld.%ld)\n",
          (long long)now.tv_sec,
          (long)now.tv_usec);
      if (!tb[NL80211_ATTR_ACK] || !tb[NL80211_ATTR_FRAME])
        sae_debug(MESHD_DEBUG, "tx frame failed!");
      break;
    default:
      sae_debug(MESHD_DEBUG, "Ignored event (%d)\n", gnlh->cmd);
      break;
  }

  return NL_SKIP;
}

static int set_authenticated_flag(
    struct netlink_config_s *nlcfg,
    unsigned char *peer) {
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

  pret =
      genlmsg_put(msg, 0, 0, genl_family_get_id(nlcfg->nl80211), 0, 0, cmd, 0);

  if (pret == NULL)
    goto nla_put_failure;

  NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, nlcfg->ifindex);
  NLA_PUT(msg, NL80211_ATTR_MAC, ETH_ALEN, peer);
  flags.mask = flags.set = (1 << NL80211_STA_FLAG_AUTHENTICATED) |
      (1 << NL80211_STA_FLAG_MFP) | (1 << NL80211_STA_FLAG_AUTHORIZED);

  if (!meshd_conf.is_secure || !meshd_conf.pmf) {
    flags.set &= ~(1 << NL80211_STA_FLAG_MFP);
  }

  NLA_PUT(msg, NL80211_ATTR_STA_FLAGS2, sizeof(flags), &flags);

  ret = send_nlmsg(nlcfg->nl_sock, msg);
  sae_debug(
      MESHD_DEBUG, "set auth flag (seq num=%d)\n", nlmsg_hdr(msg)->nlmsg_seq);
  nlmsg_free(msg);
  msg = NULL;
  if (ret < 0)
    fprintf(
        stderr,
        "Failed to set auth flag on station: %d (%s)\n",
        ret,
        strerror(-ret));
  else
    ret = 0;

  return ret;
nla_put_failure:
  nlmsg_free(msg);
  msg = NULL;
  return -ENOBUFS;
}

int set_plink_state(unsigned char *peer, int state, void *cookie) {
  struct nl_msg *msg;
  uint8_t cmd = NL80211_CMD_SET_STATION;
  int ret;
  char *pret;

  assert(cookie == &nlcfg);

  if (!peer)
    return -EINVAL;

  msg = nlmsg_alloc();

  if (!msg)
    return -ENOMEM;

  pret =
      genlmsg_put(msg, 0, 0, genl_family_get_id(nlcfg.nl80211), 0, 0, cmd, 0);

  if (pret == NULL)
    goto nla_put_failure;

  NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, nlcfg.ifindex);
  NLA_PUT(msg, NL80211_ATTR_MAC, ETH_ALEN, peer);
  NLA_PUT_U8(msg, NL80211_ATTR_STA_PLINK_STATE, state);

  ret = send_nlmsg(nlcfg.nl_sock, msg);
  sae_debug(
      MESHD_DEBUG, "set plink state (seq num=%d)\n", nlmsg_hdr(msg)->nlmsg_seq);
  nlmsg_free(msg);
  msg = NULL;
  if (ret < 0)
    fprintf(stderr, "Peer link command failed: %d (%s)\n", ret, strerror(-ret));
  else
    ret = 0;

  return ret;
nla_put_failure:
  nlmsg_free(msg);
  msg = NULL;
  return -ENOBUFS;
}

#if 0
static int set_frequency(struct netlink_config_s *nlcfg, int freq)
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
#endif

static int leave_mesh(struct netlink_config_s *nlcfg) {
  struct nl_msg *msg;
  uint8_t cmd = NL80211_CMD_LEAVE_MESH;
  int ret;
  char *pret;

  msg = nlmsg_alloc();
  if (!msg)
    return -ENOMEM;

  pret =
      genlmsg_put(msg, 0, 0, genl_family_get_id(nlcfg->nl80211), 0, 0, cmd, 0);
  if (pret == NULL)
    goto nla_put_failure;

  NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, nlcfg->ifindex);

  /*  Suppress netlink error in case we are not connected to mesh */
  nlcfg->supress_error = -ENOTCONN;
  ret = send_nlmsg(nlcfg->nl_sock, msg);
  nlmsg_free(msg);
  msg = NULL;
  if (ret < 0)
    fprintf(stderr, "Mesh leave failed: %d (%s)\n", ret, strerror(-ret));
  else
    ret = 0;

  return ret;
nla_put_failure:
  nlmsg_free(msg);
  msg = NULL;
  return -ENOBUFS;
}

static int join_mesh(struct netlink_config_s *nlcfg, struct mesh_node *mesh) {
  struct nl_msg *msg;
  struct meshd_config *mconf = mesh->conf;
  uint8_t cmd = NL80211_CMD_JOIN_MESH;
  uint8_t basic_rates[MAX_SUPP_RATES];
  int rates = 0, i;
  int ret;
  char *pret;

  assert(rsn_ie[1] == sizeof(rsn_ie) - 2);

  if (!mconf->meshid || !mconf->meshid_len)
    return -EINVAL;

  msg = nlmsg_alloc();
  if (!msg)
    return -ENOMEM;

  sae_debug(
      MESHD_DEBUG, "meshd: Starting mesh with mesh id = %s\n", mconf->meshid);

  pret =
      genlmsg_put(msg, 0, 0, genl_family_get_id(nlcfg->nl80211), 0, 0, cmd, 0);
  if (pret == NULL)
    goto nla_put_failure;

  /* configure BSSBasicRateSet in kernel MPM, which has to know about this to
   * select eligible candidates */
  for (i = 0; i < sizeof(mconf->rates); i++) {
    if (mconf->rates[i] & 0x80) {
      basic_rates[rates] = mconf->rates[i];
      rates++;
    }
  }

  sae_hexdump(MESHD_DEBUG, "basic rates:", basic_rates, rates);
  NLA_PUT(msg, NL80211_ATTR_BSS_BASIC_RATES, rates, basic_rates);

  struct nlattr *container = nla_nest_start(msg, NL80211_ATTR_MESH_CONFIG);

  if (!container)
    goto nla_put_failure;

  NLA_PUT_U8(msg, NL80211_MESHCONF_AUTO_OPEN_PLINKS, 0);
  if (mconf->path_refresh_time > 0) {
    NLA_PUT_U32(
        msg, NL80211_MESHCONF_PATH_REFRESH_TIME, mconf->path_refresh_time);
  }

  if (mconf->min_discovery_timeout > 0) {
    NLA_PUT_U16(
        msg,
        NL80211_MESHCONF_MIN_DISCOVERY_TIMEOUT,
        mconf->min_discovery_timeout);
  }

  if (mconf->hwmp_active_path_timeout > 0) {
    NLA_PUT_U32(
        msg,
        NL80211_MESHCONF_HWMP_ACTIVE_PATH_TIMEOUT,
        mconf->hwmp_active_path_timeout);
  }

  if (mconf->hwmp_net_diameter_traversal_time > 0) {
    NLA_PUT_U16(
        msg,
        NL80211_MESHCONF_HWMP_NET_DIAM_TRVS_TIME,
        mconf->hwmp_net_diameter_traversal_time);
  }

  if (mconf->hwmp_rootmode > 0) {
    NLA_PUT_U8(msg, NL80211_MESHCONF_HWMP_ROOTMODE, mconf->hwmp_rootmode);
  }

  if (mconf->hwmp_rann_interval > 0) {
    NLA_PUT_U16(
        msg, NL80211_MESHCONF_HWMP_RANN_INTERVAL, mconf->hwmp_rann_interval);
  }

  if (mconf->gate_announcements >= 0) {
    NLA_PUT_U8(
        msg, NL80211_MESHCONF_GATE_ANNOUNCEMENTS, mconf->gate_announcements);
  }

  if (mconf->hwmp_active_path_to_root_timeout > 0) {
    NLA_PUT_U32(
        msg,
        NL80211_MESHCONF_HWMP_PATH_TO_ROOT_TIMEOUT,
        mconf->hwmp_active_path_to_root_timeout);
  }

  if (mconf->hwmp_root_interval > 0) {
    NLA_PUT_U16(
        msg, NL80211_MESHCONF_HWMP_ROOT_INTERVAL, mconf->hwmp_root_interval);
  }

  nla_nest_end(msg, container);

  container = nla_nest_start(msg, NL80211_ATTR_MESH_SETUP);

  if (!container)
    goto nla_put_failure;

  /* We'll be creating stations, not the kernel */
  NLA_PUT_FLAG(msg, NL80211_MESH_SETUP_USERSPACE_MPM);

  if (mconf->is_secure) {
    /* Tell the kernel we're using SAE */
    NLA_PUT_FLAG(msg, NL80211_MESH_SETUP_USERSPACE_AUTH);
    NLA_PUT_FLAG(msg, NL80211_MESH_SETUP_USERSPACE_AMPE);
    NLA_PUT_U8(msg, NL80211_MESH_SETUP_AUTH_PROTOCOL, 0x1);
    NLA_PUT(msg, NL80211_MESH_SETUP_IE, sizeof(rsn_ie), rsn_ie);
  }

  nla_nest_end(msg, container);

  NLA_PUT_U32(msg, NL80211_ATTR_WIPHY_FREQ, mesh->freq);
  if (mesh->channel_type != CHAN_NO_HT)
    NLA_PUT_U32(msg, NL80211_ATTR_WIPHY_CHANNEL_TYPE, mesh->channel_type);

  NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, nlcfg->ifindex);
  NLA_PUT(msg, NL80211_ATTR_MESH_ID, mconf->meshid_len, mconf->meshid);

  if (mconf->mcast_rate > 0)
    NLA_PUT_U32(msg, NL80211_ATTR_MCAST_RATE, mconf->mcast_rate);

  if (mconf->beacon_interval > 0)
    NLA_PUT_U32(msg, NL80211_ATTR_BEACON_INTERVAL, mconf->beacon_interval);

  sae_debug(
      MESHD_DEBUG,
      "joining mesh %s on freq %d, mode %d\n",
      mconf->meshid,
      mesh->freq,
      mesh->channel_type);

  ret = send_nlmsg(nlcfg->nl_sock, msg);
  nlmsg_free(msg);
  msg = NULL;
  if (ret < 0)
    fprintf(stderr, "Mesh start failed: %d (%s)\n", ret, strerror(-ret));
  else
    ret = 0;

  return ret;
nla_put_failure:
  nlmsg_free(msg);
  msg = NULL;
  return -ENOBUFS;
}

void estab_peer_link(
    unsigned char *peer,
    unsigned char *mtk,
    int mtk_len,
    unsigned char *peer_mgtk,
    int peer_mgtk_len,
    unsigned int mgtk_expiration,
    unsigned char *peer_igtk,
    int peer_igtk_len,
    int peer_igtk_keyid,
    unsigned char *rates,
    unsigned short rates_len,
    void *cookie) {
  struct meshd_config *mconf;
  struct candidate *cand;
  int ret;

  assert(cookie == &nlcfg);

  if (!peer)
    return;

  cand = find_peer(peer, 0);
  if (!cand)
    return;

  mconf = cand->conf->mesh->conf;

  if (mconf->is_secure) {
    if (mtk_len != KEY_LEN_AES_CCMP || peer_mgtk_len != KEY_LEN_AES_CCMP)
      return;

    if (peer_igtk && peer_igtk_len != KEY_LEN_AES_CMAC)
      return;
  }

  sae_debug(MESHD_DEBUG, "estab with " MACSTR "\n", MAC2STR(peer));

  if (!cand->in_kernel) {
    struct info_elems elems = {};

    elems.sup_rates = cand->sup_rates;
    elems.sup_rates_len = cand->sup_rates_len;

    elems.ht_cap = (unsigned char *)&cand->ht_cap;
    elems.ht_cap_len = sizeof(cand->ht_cap);

    elems.ht_info = (unsigned char *)&cand->ht_info;
    elems.ht_info_len = sizeof(cand->ht_info);

    ret = add_unauthenticated_sta(&nlcfg, peer, &elems);
    if (ret)
      return;

    cand->in_kernel = true;
  }

  set_authenticated_flag(&nlcfg, peer);

  if (mconf->is_secure) {
    /* key to encrypt/decrypt unicast data AND mgmt traffic to/from this peer */
    install_key(&nlcfg, peer, CIPHER_CCMP, NL80211_KEYTYPE_PAIRWISE, 0, mtk);

    /* key to decrypt multicast data traffic from this peer */
    install_key(&nlcfg, peer, CIPHER_CCMP, NL80211_KEYTYPE_GROUP, 1, peer_mgtk);

    /* to check integrity of multicast mgmt frames from this peer */
    if (peer_igtk) {
      install_key(
          &nlcfg,
          peer,
          CIPHER_AES_CMAC,
          NL80211_KEYTYPE_GROUP,
          peer_igtk_keyid,
          peer_igtk);
    }
  }
}

void peer_created(unsigned char *peer) {
  struct candidate *cand;
  /*
   * We don't have to do anything here:
   *
   *  - if peer was created from SAE state machine, then
   *    it will be added to kernel when the IEs are known (e.g.
   *    on estab plink)
   *
   *  - if peer is created from a beacon, we will know the IEs
   *    and will go ahead and create the peer in new_candidate_handler.
   *
   * Validate the invariant that this is only called before the
   * is updated.
   */
  cand = find_peer(peer, 0);
  if (!cand)
    return;

  if (cand->in_kernel) {
    sae_debug(
        SAE_DEBUG_ERR,
        "attempting to create peer that is already in kernel: " MACSTR "\n",
        MAC2STR(peer));
  }
}

void peer_deleted(unsigned char *peer) {
  struct nl_msg *msg;
  uint8_t cmd = NL80211_CMD_DEL_STATION;
  int ret;
  char *pret;

  if (!peer)
    return;

  msg = nlmsg_alloc();

  if (!msg)
    return;

  pret =
      genlmsg_put(msg, 0, 0, genl_family_get_id(nlcfg.nl80211), 0, 0, cmd, 0);

  if (pret == NULL)
    goto nla_put_failure;

  NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, nlcfg.ifindex);
  NLA_PUT(msg, NL80211_ATTR_MAC, ETH_ALEN, peer);

  ret = send_nlmsg(nlcfg.nl_sock, msg);
  nlmsg_free(msg);
  msg = NULL;
  sae_debug(MESHD_DEBUG, "removing peer candidate " MACSTR "\n", MAC2STR(peer));
  if (ret < 0)
    fprintf(stderr, "Remove candidate failed: %d (%s)\n", ret, strerror(-ret));

  return;
nla_put_failure:
  nlmsg_free(msg);
  msg = NULL;
}

void fin(
    unsigned short reason,
    unsigned char *peer,
    unsigned char *buf,
    int len,
    void *cookie) {
  sae_debug(
      MESHD_DEBUG,
      "fin: %d, key len:%d peer:" MACSTR " me:" MACSTR "\n",
      reason,
      len,
      MAC2STR(peer),
      MAC2STR(mesh.mymacaddr));
  if (!reason && len) {
    if (meshd_conf.is_secure) {
      sae_hexdump(AMPE_DEBUG_KEYS, "pmk", buf, len % 80);
    }
    ampe_open_peer_link(peer, cookie);
  } else if (reason) {
    peer_deleted(peer);
  }
}

void term_handle(int i) {
  srv_cancel_main_loop(srvctx);
}

#if defined(__linux__) && !defined(__ANDROID__)
__attribute__((noreturn)) static void segv_handle(int sig) {
#ifdef __GLIBC__
  void *bt_array[64];
  size_t bt_size;
  size_t bt_index = 0;
  char **bt_syms;

  bt_size = backtrace(bt_array, 64);
  bt_syms = backtrace_symbols(bt_array, bt_size);

  sae_debug(SAE_DEBUG_ERR, "%s\n", "crash");
  while (bt_index < bt_size) {
    sae_debug(SAE_DEBUG_ERR, "%s\n", bt_syms[bt_index++]);
  }
#else
  sae_debug(
      SAE_DEBUG_ERR,
      "crash (logging a stack trace is not supported on this platform)",
      message);
#endif

  exit(126);
}
#endif /* defined(__linux__) && !defined(__ANDROID__) */

void hup_handle(int i) {
  rekey_reopen_sockets();
}

/* TODO: This config stuff should be in a common file to be shared by other
 * meshd implementations
 */

static int meshd_parse_libconfig(
    struct config_setting_t *meshd_section,
    struct meshd_config *config) {
  char *str;

  memset(config, 0, sizeof(struct meshd_config));

  if (config_setting_lookup_string(
          meshd_section, "interface", (const char **)&str)) {
    strncpy(config->interface, str, IFNAMSIZ + 1);
    if (config->interface[IFNAMSIZ] != 0) {
      fprintf(stderr, "Interface name is too long\n");
      return -1;
    }
  }

  if (config_setting_lookup_string(
          meshd_section, "meshid", (const char **)&str)) {
    strncpy(config->meshid, str, MESHD_MAX_SSID_LEN + 1);
    if (config->meshid[MESHD_MAX_SSID_LEN] != 0) {
      fprintf(stderr, "WARNING: Truncating meshid\n");
      config->meshid[MESHD_MAX_SSID_LEN] = 0;
    }
    config->meshid_len = strlen(config->meshid);
  }

#define CONFIG_LOOKUP(name, config_val, dflt)                         \
  if (CONFIG_FALSE ==                                                 \
      config_setting_lookup_int(                                      \
          meshd_section, name, (config_int_t *)&config->config_val))  \
    config->config_val = dflt;

  CONFIG_LOOKUP("channel", channel, -1);
  CONFIG_LOOKUP("mcast-rate", mcast_rate, -1);
  CONFIG_LOOKUP("beacon-interval", beacon_interval, -1);

  CONFIG_LOOKUP("is-secure", is_secure, 1);

  config_setting_lookup_int(meshd_section, "pmf", (config_int_t *)&config->pmf);

  /* Get mesh parameter */
  CONFIG_LOOKUP("path-refresh-time", path_refresh_time, -1);
  CONFIG_LOOKUP("min-discovery-timeout", min_discovery_timeout, -1);
  CONFIG_LOOKUP("gate-announcements", gate_announcements, -1);
  CONFIG_LOOKUP("hwmp-active-path-timeout", hwmp_active_path_timeout, -1);
  CONFIG_LOOKUP(
      "hwmp-net-diameter-traversal-time",
      hwmp_net_diameter_traversal_time,
      -1);
  CONFIG_LOOKUP("hwmp-rootmode", hwmp_rootmode, -1);
  CONFIG_LOOKUP("hwmp-rann-interval", hwmp_rann_interval, -1);
  CONFIG_LOOKUP(
      "hwmp-active-path-to-root-timeout",
      hwmp_active_path_to_root_timeout,
      -1);
  CONFIG_LOOKUP("hwmp-root-interval", hwmp_root_interval, -1);

  config->band = MESHD_11b;

  if (config_setting_lookup_string(
          meshd_section, "band", (const char **)&str)) {
    if (strncmp(str, "11a", 3) == 0) {
      config->band = MESHD_11a;
    } else if (strncmp(str, "11b", 3) == 0) {
      config->band = MESHD_11b;
    } else if (strncmp(str, "11g", 3) == 0) {
      config->band = MESHD_11g;
    } else {
      fprintf(stderr, "Invalid meshd band %s\n", str);
    }
  }

  config->channel_type = NL80211_CHAN_NO_HT;
  if (config_setting_lookup_string(
          meshd_section, "htmode", (const char **)&str)) {
    if (strncmp(str, "none", 4) == 0) {
      config->channel_type = NL80211_CHAN_NO_HT;
    } else if (strncmp(str, "HT20", 4) == 0) {
      config->channel_type = NL80211_CHAN_HT20;
    } else if (strncmp(str, "HT40+", 5) == 0) {
      config->channel_type = NL80211_CHAN_HT40PLUS;
    } else if (strncmp(str, "HT40-", 5) == 0) {
      config->channel_type = NL80211_CHAN_HT40MINUS;
    } else {
      sae_debug(MESHD_DEBUG, "unknown HT mode \"%s\", disabling\n", str);
    }
  }

  CONFIG_LOOKUP("rekey_enable", rekey_enable, REKEY_ENABLE_DEF);
  config->rekey_enable = (config->rekey_enable != 0);

  if (config_setting_lookup_string(
          meshd_section, "bridge", (const char **)&str)) {
    strncpy(config->bridge, str, sizeof(config->bridge));
    if (config->bridge[sizeof(config->bridge) - 1]) {
      fprintf(stderr, "Bridge name is too long\n");
      return -1;
    }
  }

  config->rekey_multicast_group_family = REKEY_MULTICAST_GROUP_FAMILY_DEF;
  config->rekey_multicast_group_address.v4.s_addr =
      REKEY_MULTICAST_GROUP_ADDRESS_DEF;
  bool groupValid = true;

  if (config_setting_lookup_string(
          meshd_section, "rekey_multicast_group", (const char **)&str)) {
    if (inet_pton(AF_INET, str, &config->rekey_multicast_group_address.v4)) {
      config->rekey_multicast_group_family = AF_INET;
      groupValid =
          IN_MULTICAST(ntohl(config->rekey_multicast_group_address.v4.s_addr));
    } else if (
        inet_pton(AF_INET6, str, &config->rekey_multicast_group_address.v6)) {
      config->rekey_multicast_group_family = AF_INET6;
      groupValid =
          IN6_IS_ADDR_MULTICAST(&config->rekey_multicast_group_address.v6);
    } else {
      groupValid = false;
    }
  }

  if (!groupValid) {
    fprintf(stderr, "Invalid rekey multicast group '%s'\n", str);
    return -1;
  }

  CONFIG_LOOKUP("rekey_ping_port", rekey_ping_port, REKEY_PING_PORT_DEF);
  if ((config->rekey_ping_port <= 0) || (config->rekey_ping_port >= 65536)) {
    fprintf(stderr, "Invalid rekey ping port %d\n", config->rekey_ping_port);
    return -1;
  }
  config->rekey_ping_port = htons(config->rekey_ping_port);

  CONFIG_LOOKUP("rekey_pong_port", rekey_pong_port, REKEY_PONG_PORT_DEF);
  if ((config->rekey_pong_port <= 0) || (config->rekey_pong_port >= 65536)) {
    fprintf(stderr, "Invalid rekey pong port %d\n", config->rekey_pong_port);
    return -1;
  }
  config->rekey_pong_port = htons(config->rekey_pong_port);

  CONFIG_LOOKUP(
      "rekey_ping_count_max", rekey_ping_count_max, REKEY_PING_COUNT_MAX_DEF);
  if (config->rekey_ping_count_max <= 0) {
    fprintf(
        stderr,
        "Invalid rekey ping count maximum %d\n",
        config->rekey_ping_count_max);
    return -1;
  }

  CONFIG_LOOKUP(
      "rekey_ping_timeout", rekey_ping_timeout, REKEY_PING_TIMEOUT_MSECS_DEF);
  if (config->rekey_ping_timeout <= 0) {
    fprintf(
        stderr, "Invalid rekey ping timeout %d\n", config->rekey_ping_timeout);
    return -1;
  }

  CONFIG_LOOKUP(
      "rekey_ping_jitter", rekey_ping_jitter, REKEY_PING_JITTER_MSECS_DEF);
  if (config->rekey_ping_jitter <= 0) {
    fprintf(
        stderr, "Invalid rekey ping jitter %d\n", config->rekey_ping_jitter);
    return -1;
  }

  CONFIG_LOOKUP(
      "rekey_reauth_count_max",
      rekey_reauth_count_max,
      REKEY_REAUTH_COUNT_MAX_DEF);
  if (config->rekey_reauth_count_max <= 0) {
    fprintf(
        stderr,
        "Invalid rekey reauthorisation count maximum %d\n",
        config->rekey_reauth_count_max);
    return -1;
  }

  CONFIG_LOOKUP(
      "rekey_ok_ping_count_max",
      rekey_ok_ping_count_max,
      REKEY_OK_PING_COUNT_MAX_DEF);
  if (config->rekey_ok_ping_count_max <= 0) {
    fprintf(
        stderr,
        "Invalid rekey ok ping count maximum %d\n",
        config->rekey_ok_ping_count_max);
    return -1;
  }

#undef CONFIG_LOOKUP

  return 0;
}

/* given the channel, find the freq in megahertz.  Borrowed from iw:
 * Copyright (c) 2007, 2008 Johannes Berg
 * Copyright (c) 2007       Andy Lutomirski
 * Copyright (c) 2007       Mike Kershaw
 * Copyright (c) 2008-2009      Luis R. Rodriguez
 */
static int channel_to_freq(int chan) {
  if (chan < 14)
    return 2407 + chan * 5;

  if (chan == 14)
    return 2484;

  /* FIXME: dot11ChannelStartingFactor (802.11-2007 17.3.8.3.2) */
  return (chan + 1000) * 5;
}

static struct ampe_cb *get_ampe_cbs() {
  static struct ampe_cb cb;
  cb.meshd_write_mgmt = meshd_write_mgmt;
  cb.meshd_set_mesh_conf = meshd_set_mesh_conf;
  cb.set_plink_state = set_plink_state;
  cb.estab_peer_link = estab_peer_link;
  cb.delete_peer = delete_peer_by_addr;
  cb.evl = get_evl_ops();
  return &cb;
}

static struct sae_cb *get_sae_cbs() {
  static struct sae_cb cb;
  cb.meshd_write_mgmt = meshd_write_mgmt;
  cb.peer_created = peer_created;
  cb.fin = fin;
  cb.evl = get_evl_ops();
  return &cb;
}

static int init(struct netlink_config_s *nlcfg, struct mesh_node *mesh) {
  int exitcode = 0;

  leave_mesh(nlcfg);

  sae_hexdump(
      MESHD_DEBUG,
      "nlcfg rates",
      (const unsigned char *)mesh->bands[mesh->band].rates,
      mesh->bands[mesh->band].n_bitrates * 2); // .rates is 16bit

  /* shouldn't happen */
  if (!mesh->bands[mesh->band].rates) {
    fprintf(stderr, "wiphy reported no rates!\n");
    exit(EXIT_FAILURE);
  }

  /* configure BSSBasicRateSet */
  set_sup_basic_rates(
      mesh->conf,
      mesh->bands[mesh->band].rates,
      mesh->bands[mesh->band].n_bitrates);

  if (ampe_initialize(mesh, get_ampe_cbs()) < 0) {
    fprintf(stderr, "cannot configure AMPE!\n");
    exit(EXIT_FAILURE);
  }

  exitcode = join_mesh(nlcfg, mesh);
  if (exitcode) {
    fprintf(stderr, "Failed to join mesh\n");
    goto out;
  }

  exitcode = register_for_auth_frames(nlcfg);
  if (exitcode)
    goto out;

  exitcode = register_for_plink_frames(nlcfg);
  if (exitcode) {
    fprintf(stderr, "cannot register for plink frame!\n");
    goto out;
  }

  if (mesh->conf->is_secure) {
    if (mesh->conf->pmf) {
      /* key to protect integrity of multicast mgmt frames tx*/
      install_key(
          nlcfg,
          NULL,
          CIPHER_AES_CMAC,
          NL80211_KEYTYPE_GROUP,
          mesh->igtk_keyid,
          mesh->igtk_tx);
    }

    /* key to encrypt multicast data traffic */
    install_key(nlcfg, NULL, CIPHER_CCMP, NL80211_KEYTYPE_GROUP, 1, mgtk_tx);
  }

out:
  return 0;
}

static int sae_parse_libconfig(
    struct config_setting_t *sae_section,
    struct sae_config *config) {
  struct config_setting_t *setting, *group;
  char *pwd;

  memset(config, 0, sizeof(struct sae_config));
  config_setting_lookup_int(
      sae_section, "debug", (config_int_t *)&config->debug);
  setting = config_setting_get_member(sae_section, "group");
  if (setting != NULL) {
    while (1) {
      group = config_setting_get_elem(setting, config->num_groups);
      if (!group)
        break;
      config->group[config->num_groups] =
          config_setting_get_int_elem(setting, config->num_groups);
      config->num_groups++;
      if (config->num_groups == SAE_MAX_EC_GROUPS)
        break;
    }
  }
  if (config_setting_lookup_string(
          sae_section, "password", (const char **)&pwd)) {
    strncpy(config->pwd, pwd, SAE_MAX_PASSWORD_LEN);
    if (config->pwd[SAE_MAX_PASSWORD_LEN - 1] != 0) {
      fprintf(stderr, "WARNING: Truncating password\n");
      config->pwd[SAE_MAX_PASSWORD_LEN - 1] = 0;
    }
  }
  config_setting_lookup_int(
      sae_section, "retrans", (config_int_t *)&config->retrans);
  config_setting_lookup_int(
      sae_section, "lifetime", (config_int_t *)&config->pmk_expiry);
  config_setting_lookup_int(
      sae_section, "thresh", (config_int_t *)&config->open_threshold);
  config_setting_lookup_int(
      sae_section, "blacklist", (config_int_t *)&config->blacklist_timeout);
  config_setting_lookup_int(
      sae_section, "giveup", (config_int_t *)&config->giveup_threshold);
  return 0;
}

int main(int argc, char *argv[]) {
  int c;
  int exitcode = 0;
  char *mesh_id = NULL;
  struct nl_sock *nlsock;
  int daemonize = 0;
  char *outfile = NULL;
  char *conffile = NULL;
  struct sae_config sae_conf;
  char *ifname = NULL;

  sae_debug_mask = SAE_DEBUG_ERR;
  signal(SIGTERM, term_handle);
  signal(SIGINT, term_handle);
  signal(SIGSEGV, segv_handle);
  signal(SIGHUP, hup_handle);

  memset(&nlcfg, 0, sizeof(nlcfg));

  for (;;) {
    c = getopt(argc, argv, "hc:o:Bi:s:");
    if (c < 0)
      break;
    switch (c) {
      case 'h':
        usage();
        return 0;
      case 'B':
        daemonize = 1;
        break;
      case 'o':
        outfile = optarg;
        break;
      case 'i':
        ifname = optarg;
        break;
      case 's':
        mesh_id = optarg;
        break;
      case 'c':
        conffile = optarg;
        break;
      default:
        usage();
        goto out;
    }
  }

  if (conffile) {
    struct config_t cfg;
    struct config_setting_t *section;

    config_init(&cfg);
    if (!config_read_file(&cfg, conffile)) {
      fprintf(
          stderr,
          "Failed to load config file %s: %s\n",
          conffile,
          config_error_text(&cfg));
      return -1;
    }
    section = config_lookup(&cfg, "authsae.sae");
    if (section == NULL) {
      fprintf(stderr, "Config file has not sae section\n");
      return -1;
    }

    if (sae_parse_libconfig(section, &sae_conf) != 0) {
      fprintf(stderr, "Failed to parse SAE configuration.\n");
      return -1;
    }

    section = config_lookup(&cfg, "authsae.meshd");
    if (section == NULL) {
      fprintf(stderr, "Config file has not meshd section\n");
      return -1;
    }
    if (meshd_parse_libconfig(section, &meshd_conf) != 0) {
      fprintf(stderr, "Failed to parse meshd configuration.\n");
      return -1;
    }

    config_destroy(&cfg);
  }

  /* command line args override config file */
  if (mesh_id) {
    if (strlen(mesh_id) > MESHD_MAX_SSID_LEN) {
      fprintf(stderr, "mesh id %s is too long\n", mesh_id);
      return -1;
    }
    strcpy(meshd_conf.meshid, mesh_id);
    meshd_conf.meshid_len = strlen(mesh_id);
  }

  if (ifname) {
    if (strlen(ifname) > IFNAMSIZ) {
      fprintf(stderr, "ifname %s is too long\n", ifname);
      return -1;
    }
    strcpy(meshd_conf.interface, ifname);
  }
  nlcfg.ifindex = if_nametoindex(meshd_conf.interface);

  /* default to channel 1 */
  if (meshd_conf.channel <= 0)
    meshd_conf.channel = 1;

  /* default to mcast-rate of 12 Mbps */
  if (meshd_conf.mcast_rate <= 0)
    meshd_conf.mcast_rate = 12;

  mesh.freq = channel_to_freq(meshd_conf.channel);
  if (mesh.freq == -1)
    return -1;
  mesh.channel_type = meshd_conf.channel_type;
  mesh.band =
      meshd_conf.band == MESHD_11a ? IEEE80211_BAND_5GHZ : IEEE80211_BAND_2GHZ;

  meshd_conf.mcast_rate = meshd_conf.mcast_rate * 10;

  /* this is the default in kernel as well, so no need to do anything else */
  meshd_conf.ht_prot_mode = IEEE80211_HT_OP_MODE_PROTECTION_NONHT_MIXED;

  /* TODO: Check if ifname is of type mesh and if it's up.
   * For now this is assumed to be true.
   */

  if (!strlen(meshd_conf.interface)) {
    fprintf(stderr, "%s: No interface specified\n", argv[0]);
    exit(EXIT_FAILURE);
  }

  exitcode = get_mac_addr(meshd_conf.interface, mesh.mymacaddr);
  if (exitcode)
    goto out;

  if (sae_initialize(meshd_conf.meshid, &sae_conf, get_sae_cbs()) < 0) {
    fprintf(stderr, "%s: cannot configure SAE, check config file!\n", argv[0]);
    exit(EXIT_FAILURE);
  }

  /* conf is good */
  mesh.conf = &meshd_conf;

  if (daemonize) {
    if (daemon(1, 0) == -1) {
      exitcode = errno;
      goto out;
    }
  }

  if (outfile) {
    if (freopen(outfile, "w", stdout) == NULL) {
      exitcode = errno;
      goto out;
    }
    dup2(fileno(stdout), fileno(stderr));
  }

  if (netlink_init(&nlcfg, event_handler)) {
    exitcode = -ESOCKTNOSUPPORT;
    goto out;
  }

  if ((srvctx = srv_create_context()) == NULL) {
    fprintf(stderr, "%s: cannot create service context!\n", argv[0]);
    exitcode = -ENOMEM;
    goto out;
  }

  rekey_init(&mesh, get_evl_ops());
  watch_ips_init(&mesh);

  /* Add netlink sockets to our event loop */
  nlsock = nlcfg.nl_sock;
  srv_add_input(srvctx, nl_socket_get_fd(nlsock), nlsock, srv_handler_wrapper);
  nlsock = nlcfg.nl_sock_event;
  srv_add_input(srvctx, nl_socket_get_fd(nlsock), nlsock, srv_handler_wrapper);

  get_wiphy(&nlcfg);

  srv_main_loop(srvctx);
  leave_mesh(&nlcfg);
out:
  watch_ips_close();
  rekey_close();
  return exitcode;
}
