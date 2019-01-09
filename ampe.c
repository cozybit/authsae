/*
 * Copyright (c) cozybit Inc., 2011
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
 */

#include "ampe.h"

#include <assert.h>
#include <errno.h>
#include <openssl/rand.h>
#include <string.h>

#include "chan.h"
#include "peer_lists.h"
#include "peers.h"
#include "rekey.h"
#include "sae.h"

/* Peer link cancel reasons */
#define MESH_LINK_CANCELLED 52
#define MESH_MAX_NEIGHBORS 53
#define MESH_CAPABILITY_POLICY_VIOLATION 54
#define MESH_CLOSE_RCVD 55
#define MESH_MAX_RETRIES 56
#define MESH_CONFIRM_TIMEOUT 57
#define MESH_SECURITY_INVALID_GTK 58
#define MESH_SECURITY_INCONSISTENT_PARAMS 59
#define MESH_SECURITY_INVALID_CAPABILITY 60

/* Mesh protocol identifiers */
#define MESH_CONFIG_PP_HWMP 1
#define MESH_CONFIG_PM_ALM 1
#define MESH_CONFIG_CC_NONE 0
#define MESH_CONFIG_SP_NEIGHBOR_OFFSET 1
#define MESH_CONFIG_AUTH_SAE 1

#ifndef BIT
#define BIT(x) (1UL << (x))
#endif

#define MESH_CAPA_ACCEPT_PEERINGS BIT(0)
#define MESH_CAPA_FORWARDING BIT(3)

#define MIC_IE_BODY_SIZE AES_BLOCK_SIZE

static const unsigned char akm_suite_selector[4] = {0x0,
                                                    0xf,
                                                    0xac,
                                                    0x8}; /*  SAE  */
static const unsigned char pw_suite_selector[4] = {0x0,
                                                   0xf,
                                                   0xac,
                                                   0x4}; /*  CCMP  */
static const unsigned char null_nonce[32] = {0};

static struct ampe_cb *cb;

/* IEs */
static unsigned char *sta_fixed_ies;
static unsigned char sta_fixed_ies_len;

/* Mesh group temporal key */
unsigned char mgtk_tx[KEY_LEN_AES_CCMP];

/* global configuration data */
static struct ampe_config ampe_conf;

enum plink_event {
  PLINK_UNDEFINED,
  OPN_ACPT,
  OPN_RJCT,
  CNF_ACPT,
  CNF_RJCT,
  CLS_ACPT,
  CLS_IGNR,
  REQ_RJCT
};

/*  For debugging use */
static const char *mpl_states[] = {[PLINK_LISTEN] = "LISTEN",
                                   [PLINK_OPN_SNT] = "OPN-SNT",
                                   [PLINK_OPN_RCVD] = "OPN-RCVD",
                                   [PLINK_CNF_RCVD] = "CNF_RCVD",
                                   [PLINK_ESTAB] = "ESTAB",
                                   [PLINK_HOLDING] = "HOLDING",
                                   [PLINK_BLOCKED] = "BLOCKED"};

static const char *mpl_events[] = {
        [PLINK_UNDEFINED] = "PLINK_UNDEFINED",
        [OPN_ACPT] = "OPN_ACPT",
        [OPN_RJCT] = "OPN_RJCT",
        [CNF_ACPT] = "CNF_ACPT",
        [CNF_RJCT] = "CNF_RJCT",
        [CLS_ACPT] = "CLS_ACPT",
        [CLS_IGNR] = "CLS_IGNR",
        [REQ_RJCT] = "REQ_RJCT",
};

static int plink_frame_tx(
    struct candidate *cand,
    enum plink_action_code action,
    unsigned short reason);

static inline void set_link_state(
    struct candidate *cand,
    enum plink_state state) {
  cand->link_state = state;
  cb->set_plink_state(cand->peer_mac, state, cand->cookie);
}

static void *memdup(const void *src, size_t size) {
  void *dst = malloc(size);

  if (dst)
    memcpy(dst, src, size);

  return dst;
}

static int plink_estab_count() {
  struct candidate *peer;
  int count = 0;

  for_each_peer(peer) {
    if (peer->link_state == PLINK_ESTAB)
      count++;
  }
  return count;
}

static int plink_free_count(struct mesh_node *mesh) {
  return MAX(mesh->conf->max_plinks - plink_estab_count(), 0);
}

static inline unsigned char *
start_of_ies(struct ieee80211_mgmt_frame *frame, int len, u16 *ie_len) {
  int offset = 0;
  switch (frame->action.action_code) {
    case PLINK_OPEN:
      offset = 2;
      break;
    case PLINK_CONFIRM:
      offset = 4;
      break;
    case PLINK_CLOSE:
      offset = 0;
  }
  if (ie_len)
    *ie_len = len - 24 - sizeof(frame->action) - offset;
  return (frame->action.u.var8 + offset);
}

static void derive_aek(struct candidate *cand) {
  unsigned char context[AES_BLOCK_SIZE];

  memcpy(context, akm_suite_selector, 4);
  if (memcmp(cand->my_mac, cand->peer_mac, ETH_ALEN) < 0) {
    memcpy(context + 4, cand->my_mac, ETH_ALEN);
    memcpy(context + 10, cand->peer_mac, ETH_ALEN);
  } else {
    memcpy(context + 4, cand->peer_mac, ETH_ALEN);
    memcpy(context + 10, cand->my_mac, ETH_ALEN);
  }

  prf(cand->pmk,
      SHA256_DIGEST_LENGTH,
      (unsigned char *)"AEK Derivation",
      strlen("AEK Derivation"),
      context,
      sizeof(context),
      cand->aek,
      SHA256_DIGEST_LENGTH * 8);

  sae_hexdump(AMPE_DEBUG_KEYS, "aek context: ", context, sizeof(context));
  sae_hexdump(AMPE_DEBUG_KEYS, "aek: ", cand->aek, sizeof(cand->aek));
}

/*
 * Determine and set the correct ht operation mode for all established peers
 * according to 802.11-2016 10.26.3.5.
 *
 * Return MESH_CONF_CHANGED_HT bit if a new operation mode was selected.
 */
static uint32_t mesh_set_ht_op_mode(struct mesh_node *mesh) {
  struct candidate *peer;
  uint32_t changed = 0;
  unsigned int ht_opmode;
  bool no_ht = false, ht20 = false;

  if (mesh->conf->channel_width == CHAN_WIDTH_20_NOHT)
    return 0;

  for_each_peer(peer) {
    if (peer->link_state != PLINK_ESTAB)
      continue;

    switch (peer->ch_width) {
      case CHAN_WIDTH_20_NOHT:
        no_ht = true;
        goto out;
      case CHAN_WIDTH_20:
        ht20 = true;
        break;
      default:
        break;
    }
  }

out:
  if (no_ht)
    ht_opmode = IEEE80211_HT_OP_MODE_PROTECTION_NONHT_MIXED;
  else if (ht20 && mesh->conf->channel_width > CHAN_WIDTH_20)
    ht_opmode = IEEE80211_HT_OP_MODE_PROTECTION_20MHZ;
  else
    ht_opmode = IEEE80211_HT_OP_MODE_PROTECTION_NONE;

  if (ht_opmode != mesh->conf->ht_prot_mode) {
    sae_debug(MESHD_DEBUG, "changing ht protection mode to: %d\n", ht_opmode);
    mesh->conf->ht_prot_mode = ht_opmode;
    changed = MESH_CONF_CHANGED_HT;
  }

  return changed;
}

static void peer_ampe_init(
    struct ampe_config *aconf,
    struct candidate *cand,
    void *cookie) {
  le16 llid;

  assert(cand);

  RAND_bytes((unsigned char *)&llid, sizeof(llid));
  RAND_bytes(cand->my_nonce, sizeof(cand->my_nonce));
  cand->cookie = cookie;
  cand->my_lid = llid;
  cand->peer_lid = 0;
  set_link_state(cand, PLINK_LISTEN);
  cand->timeout = aconf->retry_timeout_ms;
  cand->conf = aconf;

  memset(cand->mtk, 0, sizeof(cand->mtk));
  memset(cand->mgtk, 0, sizeof(cand->mgtk));
  memset(cand->igtk, 0, sizeof(cand->igtk));
  cand->has_igtk = false;

  if (aconf->mesh->conf->is_secure) {
    derive_aek(cand);
    siv_init(&cand->sivctx, cand->aek, SIV_256);
  }
}

/**
 * fsm_restart - restart a mesh peer link finite state machine
 *
 * @cand: mesh peer link to restart
 *
 * */
static inline void fsm_restart(struct candidate *cand) {
  sae_debug(
      AMPE_DEBUG_FSM,
      "Deleting peer " MACSTR " to restart FSM\n",
      MAC2STR(cand->peer_mac));

  if (cb->delete_peer)
    cb->delete_peer(cand->peer_mac);
}

static void plink_timer(void *data) {
  le16 reason;
  struct candidate *cand;

  cand = (struct candidate *)data;

  assert(cand);

  sae_debug(
      AMPE_DEBUG_FSM,
      "Mesh plink timer for " MACSTR " fired on state %s\n",
      MAC2STR(cand->peer_mac),
      mpl_states[(cand->link_state > PLINK_BLOCKED) ? PLINK_UNDEFINED
                                                    : cand->link_state]);

  reason = 0;

  switch (cand->link_state) {
    case PLINK_OPN_RCVD:
    case PLINK_OPN_SNT:
      /* retry timer */
      sae_debug(
          AMPE_DEBUG_FSM,
          "Mesh plink:retries %d of %d\n",
          cand->retries,
          cand->conf->max_retries);
      if (cand->retries < cand->conf->max_retries) {
        cand->timeout = cand->conf->retry_timeout_ms;
        sae_debug(
            AMPE_DEBUG_FSM,
            "Mesh plink for " MACSTR " (retry, timeout): %d %d\n",
            MAC2STR(cand->peer_mac),
            cand->retries,
            cand->timeout);
        ++cand->retries;
        cb->evl->rem_timeout(cand->t2);
        cand->t2 =
            cb->evl->add_timeout(SRV_MSEC(cand->timeout), plink_timer, cand);
        plink_frame_tx(cand, PLINK_OPEN, 0);
        break;
      }
      reason = MESH_MAX_RETRIES;
    /* no break / fall through on else */
    case PLINK_CNF_RCVD:
      /* confirm timer */
      if (!reason)
        reason = MESH_CONFIRM_TIMEOUT;
      set_link_state(cand, PLINK_HOLDING);
      cb->evl->rem_timeout(cand->t2);
      cand->t2 = cb->evl->add_timeout(
          SRV_MSEC(cand->conf->holding_timeout_ms), plink_timer, cand);
      plink_frame_tx(cand, PLINK_CLOSE, reason);
      break;
    case PLINK_HOLDING:
      /* holding timer */
      fsm_restart(cand);
      break;
    case PLINK_ESTAB:
      /* nothing to do */
      break;
    default:
      sae_debug(
          AMPE_DEBUG_FSM,
          "Timeout for peer " MACSTR " in state %d\n",
          MAC2STR(cand->peer_mac),
          cand->link_state);
      break;
  }
}

/**
 * protect_frame - add in-place the MIC and the (encrypted) AMPE ie to a frame
 * @cand:       The candidate this frame is destined for
 * @mgmt:       The frame, populated with all the information elements  up to
 * where the MIC information element should go
 * @mic_start:  Pointer to where the mic and AMPE ies are to be written.  Should
 * point to the start of the IE, not the IE body.
 * @len:        On input, the total buffer size that contains this frame.  On
 * output, the actual lenght of the frame
 *              including the two information elements added by this function.
 *
 * Returns: The zero on success, or some error.
 */
static int protect_frame(
    struct candidate *cand,
    struct ieee80211_mgmt_frame *mgmt,
    unsigned char *mic_start,
    int *len) {
  unsigned char *clear_ampe_ie;
  unsigned char *ie;
  unsigned short cat_to_mic_len;
  struct mesh_node *mesh = cand->conf->mesh;
  size_t ampe_ie_len;
  unsigned char ftype = mgmt->action.action_code;
  le16 igtk_keyid;

  assert(mic_start && cand && mgmt && len);

  ampe_ie_len = sizeof(struct ampe_ie);

  if (ftype != PLINK_CLOSE) {
    /* MGTK + RSC + Exp */
    ampe_ie_len += 16 + 8 + 4;

    if (mesh->conf->pmf) {
      /* IGTK KeyId + IPN + IGTK */
      ampe_ie_len += 2 + 6 + 16;
    }
  }

  if (mic_start + MIC_IE_BODY_SIZE + 2 + 2 + ampe_ie_len -
          (unsigned char *)mgmt >
      *len) {
    sae_debug(AMPE_DEBUG_KEYS, "protect frame: buffer too small\n");
    return -EINVAL;
  }

  clear_ampe_ie = malloc(ampe_ie_len + 2);
  if (!clear_ampe_ie) {
    sae_debug(AMPE_DEBUG_KEYS, "protect frame: out of memory\n");
    return -ENOMEM;
  }

  /*  IE: AMPE */
  ie = clear_ampe_ie;
  *ie++ = IEEE80211_EID_AMPE;
  *ie++ = ampe_ie_len;
  memcpy(ie, pw_suite_selector, 4);
  ie += 4;
  memcpy(ie, cand->my_nonce, 32);
  ie += 32;
  memcpy(ie, cand->peer_nonce, 32);
  ie += 32;

  if (ftype != PLINK_CLOSE) {
    memcpy(ie, mgtk_tx, 16);
    ie += 16;
    memset(ie, 0, 8); /*  TODO: Populate Key RSC */
    ie += 8;
    memset(ie, 0xff, 4); /*  expire in 13 decades or so */
    ie += 4;

    if (mesh->conf->pmf) {
      igtk_keyid = htole16(mesh->igtk_keyid);
      memcpy(ie, &igtk_keyid, 2);
      ie += 2;
      memcpy(ie, mesh->igtk_ipn, 6);
      ie += 6;
      memcpy(ie, mesh->igtk_tx, 16);
      ie += 16;
    }
  }

  /* IE: MIC */
  ie = mic_start;
  *ie++ = IEEE80211_EID_MIC;
  *ie++ = MIC_IE_BODY_SIZE;

  cat_to_mic_len = mic_start - (unsigned char *)&mgmt->action;
  siv_encrypt(
      &cand->sivctx,
      clear_ampe_ie,
      ie + MIC_IE_BODY_SIZE,
      ampe_ie_len + 2,
      ie,
      3,
      cand->my_mac,
      ETH_ALEN,
      cand->peer_mac,
      ETH_ALEN,
      &mgmt->action,
      cat_to_mic_len);

  *len = mic_start - (unsigned char *)mgmt + ampe_ie_len + 2 +
      MIC_IE_BODY_SIZE + 2;

  sae_debug(
      AMPE_DEBUG_KEYS,
      "Protecting frame from " MACSTR " to " MACSTR "\n",
      MAC2STR(cand->my_mac),
      MAC2STR(cand->peer_mac));
  sae_debug(
      AMPE_DEBUG_KEYS,
      "Checking tricky lengths of protected frame %d, %zu\n",
      cat_to_mic_len,
      ampe_ie_len + 2);

  sae_hexdump(
      AMPE_DEBUG_KEYS,
      "SIV- Put AAD[3]: ",
      (unsigned char *)&mgmt->action,
      cat_to_mic_len);

  free(clear_ampe_ie);

  return 0;
}

static bool protection_is_valid(
    struct candidate *cand,
    struct ieee80211_mgmt_frame *mgmt,
    int len,
    struct info_elems *elems) {
  unsigned char *clear_ampe_ie;
  struct info_elems ies_parsed;
  struct mesh_node *mesh = cand->conf->mesh;
  unsigned short ampe_ie_len, cat_to_mic_len;
  int r;
  unsigned int *key_expiration_p;
  unsigned char ftype = mgmt->action.action_code;
  unsigned char *gtkdata, *igtkdata;

  assert(len && cand && mgmt);

  if (!mesh->conf->is_secure)
    return true;

  if (!elems->mic || elems->mic_len != MIC_IE_BODY_SIZE) {
    sae_debug(AMPE_DEBUG_KEYS, "Verify frame: invalid MIC\n");
    return false;
  }

  /*
   *  ampe_ie_len is the length of the ciphertext (the encrypted
   *  AMPE IE) and it needs to be inferred from the total frame
   *  size
   */
  ampe_ie_len = len - (elems->mic + elems->mic_len - (unsigned char *)mgmt);

  /* expect at least MGTK + RSC + expiry for open/confirm */
  if (ftype != PLINK_CLOSE &&
      ampe_ie_len < 2 + sizeof(struct ampe_ie) + 16 + 8 + 4) {
    sae_debug(AMPE_DEBUG_KEYS, "Verify frame: AMPE IE too small\n");
    return false;

    /* if PMF, then we also need IGTKData */
    if (mesh->conf->pmf) {
      if (ampe_ie_len <
          2 + sizeof(struct ampe_ie) + 16 + 8 + 4 + 2 + 6 + 16 /* IGTKData */) {
        sae_debug(AMPE_DEBUG_KEYS, "Verify frame: AMPE IE missing IGTK\n");
        return false;
      }
    }
  }

  clear_ampe_ie = malloc(ampe_ie_len);
  if (!clear_ampe_ie) {
    sae_debug(AMPE_DEBUG_KEYS, "Verify frame: out of memory\n");
    return false;
  }

  /*
   *  cat_to_mic_len is the length of the contents of the frame
   *  from the category (inclusive) to the mic (exclusive)
   */
  cat_to_mic_len = elems->mic - 2 - (unsigned char *)&mgmt->action;
  r = siv_decrypt(
      &cand->sivctx,
      elems->mic + elems->mic_len,
      clear_ampe_ie,
      ampe_ie_len,
      elems->mic,
      3,
      cand->peer_mac,
      ETH_ALEN,
      cand->my_mac,
      ETH_ALEN,
      &mgmt->action,
      cat_to_mic_len);

  sae_debug(
      AMPE_DEBUG_KEYS,
      "Checking protection to " MACSTR " from " MACSTR "\n",
      MAC2STR(cand->my_mac),
      MAC2STR(cand->peer_mac));

  sae_debug(
      AMPE_DEBUG_KEYS,
      "Len checking cat-to-mic len:%d ampe ie full length: %d\n",
      cat_to_mic_len,
      ampe_ie_len);

  sae_hexdump(
      AMPE_DEBUG_KEYS,
      "SIV- Got AAD[3]: ",
      (unsigned char *)&mgmt->action,
      cat_to_mic_len);

  if (r != 1) {
    sae_debug(AMPE_DEBUG_KEYS, "Protection check failed\n");
    free(clear_ampe_ie);
    return false;
  }

  if (ampe_ie_len != clear_ampe_ie[1] + 2) {
    sae_debug(
        AMPE_DEBUG_KEYS,
        "AMPE -Invalid length (expected %d, got %d)\n",
        ampe_ie_len,
        clear_ampe_ie[1] + 2);
    free(clear_ampe_ie);
    return false;
  }

  sae_hexdump(AMPE_DEBUG_KEYS, "AMPE IE: ", clear_ampe_ie, ampe_ie_len);

  if (ftype == PLINK_CLOSE)
    return true;

  parse_ies(clear_ampe_ie, ampe_ie_len, &ies_parsed);

  if (memcmp(ies_parsed.ampe->peer_nonce, null_nonce, 32) != 0 &&
      memcmp(ies_parsed.ampe->peer_nonce, cand->my_nonce, 32) != 0) {
    sae_hexdump(
        AMPE_DEBUG_KEYS, "IE peer_nonce ", ies_parsed.ampe->peer_nonce, 32);
    sae_debug(AMPE_DEBUG_KEYS, "Unexpected nonce\n");
    free(clear_ampe_ie);
    return false;
  }
  memcpy(cand->peer_nonce, ies_parsed.ampe->local_nonce, 32);

  gtkdata = ies_parsed.ampe->variable;

  memcpy(cand->mgtk, gtkdata, sizeof(cand->mgtk));
  sae_hexdump(
      AMPE_DEBUG_KEYS, "Received mgtk: ", cand->mgtk, sizeof(cand->mgtk));
  key_expiration_p = (unsigned int *)(gtkdata + 16 + 8);
  cand->mgtk_expiration = le32toh(*key_expiration_p);

  igtkdata = gtkdata + 16 + 8 + 4;
  if (mesh->conf->pmf) {
    cand->igtk_keyid = le16toh(*(u16 *)igtkdata);
    igtkdata += 2 + 6;
    memcpy(cand->igtk, igtkdata, sizeof(cand->igtk));
    cand->has_igtk = true;
    sae_hexdump(
        AMPE_DEBUG_KEYS, "Received igtk: ", cand->igtk, sizeof(cand->igtk));
  }
  free(clear_ampe_ie);
  return true;
}

static int plink_frame_tx(
    struct candidate *cand,
    enum plink_action_code action,
    unsigned short reason) {
  unsigned char *buf;
  struct ieee80211_mgmt_frame *mgmt;
  struct mesh_node *mesh;
  struct ieee80211_supported_band *sband;
  struct ht_cap_ie *ht_cap;
  struct ht_op_ie *ht_op;
  struct vht_op_ie *vht_op;
  unsigned char *ie_len_ptr;
  int len;
  int ret;
  unsigned char *ies;
  unsigned char *pos;
  u16 peering_proto;
  u16 close_reason;
  size_t alloc_len;
  int peer_count;
  unsigned char mesh_capa;

  assert(cand);
  assert(cand->conf);

  mesh = cand->conf->mesh;
  sband = &mesh->bands[mesh->band];

  alloc_len = sizeof(struct ieee80211_mgmt_frame) + 2 + /* capability info */
      2 + /* aid */
      sta_fixed_ies_len + 2 + mesh->conf->meshid_len + /* mesh id */
      2 + 7 + /* mesh config */
      2 + 8 + sizeof(cand->pmkid) + /* mesh peering management */
      2 + sizeof(struct ht_cap_ie) + /* HT capabilities */
      2 + sizeof(struct ht_op_ie) + /* HT operation */
      2 + 12 + /* VHT capabilities */
      2 + 5 + /* VHT operation */
      2 + 120 + /* AMPE, without Key Replay counter, 16 byte keys */
      2 + MIC_IE_BODY_SIZE; /* MIC */

  buf = calloc(1, alloc_len);
  if (!buf)
    return -1;

  sae_debug(AMPE_DEBUG_FSM, "Mesh plink: Sending plink action %d\n", action);

  mgmt = (struct ieee80211_mgmt_frame *)buf;
  mgmt->frame_control =
      htole16((IEEE802_11_FC_TYPE_MGMT << 2 | IEEE802_11_FC_STYPE_ACTION << 4));

  memcpy(mgmt->da, cand->peer_mac, ETH_ALEN);
  memcpy(mgmt->sa, cand->my_mac, ETH_ALEN);
  memcpy(mgmt->bssid, cand->my_mac, ETH_ALEN);
  mgmt->action.category = IEEE80211_CATEGORY_SELF_PROTECTED;
  mgmt->action.action_code = action;
  pos = mgmt->action.u.var8;

  if (action != PLINK_CLOSE) {
    /* capability info */
    *pos++ = (mesh->conf->is_secure) ? 0x10 : 0;
    *pos++ = 0;
    if (action == PLINK_CONFIRM) {
      /* AID */
      uint16_t *aid = (uint16_t *)pos;
      *aid = ieee_order(cand->association_id);
      pos += 2;
    }
  }

  ies = start_of_ies(mgmt, len, NULL);

  /* IE: All the static IEs */
  memcpy(ies, sta_fixed_ies, sta_fixed_ies_len);
  ies += sta_fixed_ies_len;

  /* IE: Mesh ID element */
  *ies++ = IEEE80211_EID_MESH_ID;
  *ies++ = mesh->conf->meshid_len;
  memcpy((char *)ies, mesh->conf->meshid, mesh->conf->meshid_len);
  ies += mesh->conf->meshid_len;

  /* IE: mesh config */
  *ies++ = IEEE80211_EID_MESH_CONFIG;
  *ies++ = 7;
  *ies++ = MESH_CONFIG_PP_HWMP;
  *ies++ = MESH_CONFIG_PM_ALM;
  *ies++ = MESH_CONFIG_CC_NONE;
  *ies++ = MESH_CONFIG_SP_NEIGHBOR_OFFSET;

  if (mesh->conf->is_secure) {
    *ies++ = MESH_CONFIG_AUTH_SAE;
  } else {
    *ies++ = 0;
  }

  /* formation info */
  peer_count = plink_estab_count();
  *ies++ = MIN(peer_count, 63) << 1;

  mesh_capa = MESH_CAPA_FORWARDING;
  if (peer_count < mesh->conf->max_plinks)
    mesh_capa |= MESH_CAPA_ACCEPT_PEERINGS;
  *ies++ = mesh_capa;

  /* IE: Mesh Peering Management element */
  *ies++ = IEEE80211_EID_MESH_PEERING;
  ie_len_ptr = ies;
  ies++;

  if (mesh->conf->is_secure) {
    peering_proto = htole16(1);
  } else {
    peering_proto = 0;
  }
  memcpy(ies, &peering_proto, 2);
  ies += 2;

  memcpy(ies, &cand->my_lid, 2);
  ies += 2;
  if (cand->peer_lid && (action != PLINK_OPEN)) {
    memcpy(ies, &cand->peer_lid, 2);
    ies += 2;
  }
  if (action == PLINK_CLOSE) {
    close_reason = htole16(reason);
    memcpy(ies, &close_reason, 2);
    ies += 2;
  }

  if (mesh->conf->is_secure) {
    memcpy(ies, cand->pmkid, sizeof(cand->pmkid));
    ies += sizeof(cand->pmkid);
  }
  *ie_len_ptr = ies - ie_len_ptr - 1;

  if (action != PLINK_CLOSE &&
      mesh->conf->channel_width != CHAN_WIDTH_20_NOHT &&
      sband->ht_cap.ht_supported) {
    /* HT IEs */
    *ies++ = IEEE80211_EID_HT_CAPABILITY;
    *ies++ = sizeof(struct ht_cap_ie);
    ht_cap = (struct ht_cap_ie *)ies;
    ht_cap->cap_info = htole16(sband->ht_cap.cap);
    ht_cap->ampdu_params_info =
        sband->ht_cap.ampdu_factor | (sband->ht_cap.ampdu_density << 2);
    memcpy(&ht_cap->mcs, &sband->ht_cap.mcs, sizeof(struct mcs_info));
    /* mac80211 apparently ignores the rest */
    ies += sizeof(*ht_cap);

    *ies++ = IEEE80211_EID_HT_OPERATION;
    *ies++ = sizeof(struct ht_op_ie);
    ht_op = (struct ht_op_ie *)ies;
    ht_op->primary_chan =
        ieee80211_frequency_to_channel(mesh->conf->control_freq);
    switch (mesh->conf->channel_width) {
      case CHAN_WIDTH_40:
        if (mesh->conf->center_freq1 < mesh->conf->control_freq)
          ht_op->ht_param = IEEE80211_HT_PARAM_CHA_SEC_BELOW;
        else
          ht_op->ht_param = IEEE80211_HT_PARAM_CHA_SEC_ABOVE;
        break;
      case CHAN_WIDTH_20:
      default:
        ht_op->ht_param = IEEE80211_HT_PARAM_CHA_SEC_NONE;
        break;
    }
    if ((sband->ht_cap.cap & IEEE80211_HT_CAP_SUP_WIDTH_20_40) &&
        mesh->conf->channel_width > CHAN_WIDTH_20)
      ht_op->ht_param |= IEEE80211_HT_PARAM_CHAN_WIDTH_ANY;

    ht_op->operation_mode = htole16(mesh->conf->ht_prot_mode);
    memset(ht_op->basic_set, 0, 16);
    ht_op->basic_set[0] = 0xff; /* mandatory HT phy rates */
    ies += sizeof(*ht_op);
  }

  if (action != PLINK_CLOSE &&
      mesh->conf->channel_width != CHAN_WIDTH_20_NOHT &&
      sband->vht_cap.vht_supported) {
    *ies++ = IEEE80211_EID_VHT_CAPABILITY;
    *ies++ = sizeof(sband->vht_cap.cap) + sizeof(sband->vht_cap.mcs);
    memcpy(ies, &sband->vht_cap.cap, sizeof(sband->vht_cap.cap));
    ies += sizeof(sband->vht_cap.cap);
    memcpy(ies, &sband->vht_cap.mcs, sizeof(sband->vht_cap.mcs));
    ies += sizeof(sband->vht_cap.mcs);

    *ies++ = IEEE80211_EID_VHT_OPERATION;
    *ies++ = 5;
    vht_op = (struct vht_op_ie *)ies;
    switch (mesh->conf->channel_width) {
      case CHAN_WIDTH_80:
      case CHAN_WIDTH_80P80:
      case CHAN_WIDTH_160:
        vht_op->width = 1;
        break;
      default:
        vht_op->width = 0;
    }
    vht_op->center_chan1 =
        ieee80211_frequency_to_channel(mesh->conf->center_freq1);
    vht_op->center_chan2 =
        ieee80211_frequency_to_channel(mesh->conf->center_freq2);

    /* TODO allow configuring this for mixed capability STAs;
     * see 802.11-2016 11.40.7
     */
    memcpy(
        &vht_op->basic_set,
        &sband->vht_cap.mcs.rx_mcs_mask,
        sizeof(vht_op->basic_set));
    ies += sizeof(*vht_op);
  }

  if (mesh->conf->is_secure) {
    /* IE: Add MIC and encrypted AMPE */
    len = alloc_len;
    ret = protect_frame(cand, (struct ieee80211_mgmt_frame *)buf, ies, &len);
    if (ret) {
      sae_debug(SAE_DEBUG_ERR, "Failed to protect frame\n");
      free(buf);
      return ret;
    }
  } else {
    len = ies - buf;
  }

  if (cb->meshd_write_mgmt((char *)buf, len, cand->cookie) != len) {
    sae_debug(
        SAE_DEBUG_ERR,
        "can't send a peering "
        "frame to " MACSTR "\n",
        MAC2STR(cand->peer_mac));
  }
  free(buf);
  return 0;
}

static void derive_mtk(struct candidate *cand) {
  unsigned char context[84];
  unsigned char *p;

  if (!ampe_conf.mesh->conf->is_secure)
    return;

  p = context;
  if (memcmp(cand->my_nonce, cand->peer_nonce, 32) < 0) {
    memcpy(p, cand->my_nonce, 32);
    memcpy(p + 32, cand->peer_nonce, 32);
  } else {
    memcpy(p, cand->peer_nonce, 32);
    memcpy(p + 32, cand->my_nonce, 32);
  }
  p += 64;

  if (le16toh(cand->my_lid) < le16toh(cand->peer_lid)) {
    memcpy(p, &cand->my_lid, 2);
    memcpy(p + 2, &cand->peer_lid, 2);
  } else {
    memcpy(p, &cand->peer_lid, 2);
    memcpy(p + 2, &cand->my_lid, 2);
  }
  p += 4;

  memcpy(p, akm_suite_selector, sizeof(akm_suite_selector));
  p += sizeof(akm_suite_selector);

  if (memcmp(cand->my_mac, cand->peer_mac, ETH_ALEN) < 0) {
    memcpy(p, cand->my_mac, ETH_ALEN);
    memcpy(p + ETH_ALEN, cand->peer_mac, ETH_ALEN);
  } else {
    memcpy(p, cand->peer_mac, ETH_ALEN);
    memcpy(p + ETH_ALEN, cand->my_mac, ETH_ALEN);
  }
  p += 12;

  assert(p - context <= sizeof(context));

  prf(cand->pmk,
      SHA256_DIGEST_LENGTH,
      (unsigned char *)"Temporal Key Derivation",
      strlen("Temporal Key Derivation"),
      context,
      sizeof(context),
      cand->mtk,
      16 * 8);

  sae_hexdump(AMPE_DEBUG_KEYS, "mtk context: ", context, sizeof(context));
  sae_hexdump(AMPE_DEBUG_KEYS, "mtk: ", cand->mtk, sizeof(cand->mtk));
}

static uint32_t do_estab_peer_link(struct candidate *cand) {
  uint32_t changed;
  derive_mtk(cand);
  cb->estab_peer_link(
      cand->peer_mac,
      cand->mtk,
      sizeof(cand->mtk),
      cand->mgtk,
      sizeof(cand->mgtk),
      cand->mgtk_expiration,
      (cand->has_igtk) ? cand->igtk : NULL,
      (cand->has_igtk) ? sizeof(cand->igtk) : 0,
      cand->igtk_keyid,
      cand->sup_rates,
      cand->sup_rates_len,
      cand->cookie);
  set_link_state(cand, PLINK_ESTAB);
  changed = mesh_set_ht_op_mode(cand->conf->mesh);

  sae_debug(
      AMPE_DEBUG_FSM,
      "Mesh plink with " MACSTR " ESTABLISHED\n",
      MAC2STR(cand->peer_mac));
  rekey_verify_peer(cand);
  return changed;
}

static void fsm_step(struct candidate *cand, enum plink_event event) {
  struct ampe_config *aconf = cand->conf;
  unsigned short reason = 0;
  uint32_t changed = 0;

  switch (cand->link_state) {
    case PLINK_LISTEN:
      switch (event) {
        case CLS_ACPT:
          fsm_restart(cand);
          break;
        case OPN_ACPT:
          cand->timeout = aconf->retry_timeout_ms;
          cb->evl->rem_timeout(cand->t2);
          cand->t2 =
              cb->evl->add_timeout(SRV_MSEC(cand->timeout), plink_timer, cand);
          set_link_state(cand, PLINK_OPN_RCVD);
          plink_frame_tx(cand, PLINK_OPEN, 0);
          plink_frame_tx(cand, PLINK_CONFIRM, 0);
          break;
        default:
          break;
      }
      break;

    case PLINK_OPN_SNT:
      switch (event) {
        case OPN_RJCT:
        case CNF_RJCT:
        case REQ_RJCT:
          reason = MESH_CAPABILITY_POLICY_VIOLATION;
        /* no break */
        case CLS_ACPT:
          if (!reason)
            reason = MESH_CLOSE_RCVD;
          set_link_state(cand, PLINK_HOLDING);
          cand->timeout = aconf->holding_timeout_ms;
          cb->evl->rem_timeout(cand->t2);
          cand->t2 =
              cb->evl->add_timeout(SRV_MSEC(cand->timeout), plink_timer, cand);
          plink_frame_tx(cand, PLINK_CLOSE, reason);
          break;
        case OPN_ACPT:
          /* retry timer is left untouched */
          set_link_state(cand, PLINK_OPN_RCVD);
          plink_frame_tx(cand, PLINK_CONFIRM, 0);
          break;
        case CNF_ACPT:
          set_link_state(cand, PLINK_CNF_RCVD);
          cand->timeout = aconf->confirm_timeout_ms;
          cb->evl->rem_timeout(cand->t2);
          cand->t2 =
              cb->evl->add_timeout(SRV_MSEC(cand->timeout), plink_timer, cand);
          break;
        default:
          break;
      }
      break;

    case PLINK_OPN_RCVD:
      switch (event) {
        case OPN_RJCT:
        case CNF_RJCT:
        case REQ_RJCT:
          reason = MESH_CAPABILITY_POLICY_VIOLATION;
        /* no break */
        case CLS_ACPT:
          if (!reason)
            reason = MESH_CLOSE_RCVD;
          set_link_state(cand, PLINK_HOLDING);
          cand->timeout = aconf->holding_timeout_ms;
          cb->evl->rem_timeout(cand->t2);
          cand->t2 =
              cb->evl->add_timeout(SRV_MSEC(cand->timeout), plink_timer, cand);
          plink_frame_tx(cand, PLINK_CLOSE, reason);
          break;
        case OPN_ACPT:
          plink_frame_tx(cand, PLINK_CONFIRM, 0);
          break;
        case CNF_ACPT:
          changed |= do_estab_peer_link(cand);
          break;
        default:
          break;
      }
      break;

    case PLINK_CNF_RCVD:
      switch (event) {
        case OPN_RJCT:
        case CNF_RJCT:
        case REQ_RJCT:
          reason = MESH_CAPABILITY_POLICY_VIOLATION;
        /* no break */
        case CLS_ACPT:
          if (!reason)
            reason = MESH_CLOSE_RCVD;
          set_link_state(cand, PLINK_HOLDING);
          cand->timeout = aconf->holding_timeout_ms;
          cb->evl->rem_timeout(cand->t2);
          cand->t2 =
              cb->evl->add_timeout(SRV_MSEC(cand->timeout), plink_timer, cand);
          plink_frame_tx(cand, PLINK_CLOSE, reason);
          break;
        case OPN_ACPT:
          changed |= do_estab_peer_link(cand);
          plink_frame_tx(cand, PLINK_CONFIRM, 0);
          break;
        default:
          break;
      }
      break;

    case PLINK_ESTAB:
      switch (event) {
        case OPN_RJCT:
        case CNF_RJCT:
        case REQ_RJCT:
          reason = MESH_CAPABILITY_POLICY_VIOLATION;
        case CLS_ACPT:
          if (!reason)
            reason = MESH_CLOSE_RCVD;
          set_link_state(cand, PLINK_HOLDING);
          cand->timeout = aconf->holding_timeout_ms;
          cb->evl->rem_timeout(cand->t2);
          cand->t2 =
              cb->evl->add_timeout(SRV_MSEC(cand->timeout), plink_timer, cand);
          changed |= mesh_set_ht_op_mode(cand->conf->mesh);
          plink_frame_tx(cand, PLINK_CLOSE, reason);
          break;
        case OPN_ACPT:
          plink_frame_tx(cand, PLINK_CONFIRM, 0);
          break;
        default:
          break;
      }
      break;
    case PLINK_HOLDING:
      switch (event) {
        case CLS_ACPT:
          fsm_restart(cand);
          break;
        case OPN_ACPT:
        case CNF_ACPT:
        case OPN_RJCT:
        case CNF_RJCT:
        case REQ_RJCT:
          plink_frame_tx(cand, PLINK_CLOSE, reason);
          break;
        default:
          break;
      }
      break;
    default:
      sae_debug(AMPE_DEBUG_FSM, "Unsupported event transition %d", event);
      break;
  }

  if (changed)
    cb->meshd_set_mesh_conf(cand->conf->mesh, changed);
}

#define PLINK_GET_LLID(p) (p + 2)
#define PLINK_GET_PLID(p) (p + 4)

/**
 * ampe_open_peer_link - attempt to establish a peer link
 * @peer:      MAC address of the candidate peer
 * @cookie:    Opaque cookie that will be returned to the caller along with
 *             frames to be transmitted.
 *
 * Returns 0 or a negative error.
 */
int ampe_open_peer_link(unsigned char *peer_mac, void *cookie) {
  struct candidate *cand;

  assert(peer_mac);

  if ((cand = find_peer(peer_mac, 0)) == NULL) {
    sae_debug(
        AMPE_DEBUG_FSM,
        "Mesh plink: Attempt to peer with "
        " non-authed peer\n");
    return -EPERM;
  }

  peer_ampe_init(&ampe_conf, cand, cookie);
  set_link_state(cand, PLINK_OPN_SNT);
  cb->evl->rem_timeout(cand->t2);
  cand->t2 = cb->evl->add_timeout(SRV_MSEC(cand->timeout), plink_timer, cand);

  sae_debug(
      AMPE_DEBUG_FSM,
      "Mesh plink: starting establishment "
      "with " MACSTR "\n",
      MAC2STR(peer_mac));

  return plink_frame_tx(cand, PLINK_OPEN, 0);
}

int start_peer_link(unsigned char *peer_mac, unsigned char *me, void *cookie) {
  return ampe_open_peer_link(peer_mac, cookie);
}

int ampe_close_peer_link(unsigned char *peer_mac) {
  struct candidate *cand;

  assert(peer_mac);

  if ((cand = find_peer(peer_mac, 0)) == NULL) {
    sae_debug(
        AMPE_DEBUG_FSM,
        "Mesh plink: Attempt to close link with non-existent peer\n");
    return -EPERM;
  }

  if (!cand->conf) {
    /*
     * This can happen if we get a delete event for a station but they
     * haven't yet advanced to link establishment phase.  No need to send
     * a close then.
     */
    sae_debug(
        AMPE_DEBUG_FSM,
        "Mesh plink: not sending close to uninitialized peer " MACSTR "\n",
        MAC2STR(peer_mac));
    return -EPERM;
  }

  sae_debug(
      AMPE_DEBUG_FSM,
      "Mesh plink: closing link with " MACSTR "\n",
      MAC2STR(peer_mac));

  return plink_frame_tx(cand, PLINK_CLOSE, MESH_LINK_CANCELLED);
}

static uint32_t get_basic_rates(struct info_elems *elems) {
  int i, bit = 0;
  uint32_t basic_rates = 0;

  if (elems->sup_rates) {
    for (i = 0; i < elems->sup_rates_len; i++)
      if (elems->sup_rates[i] & 0x80)
        basic_rates |= 1 << bit++;
  }

  if (elems->ext_rates) {
    for (i = 0; i < elems->ext_rates_len; i++)
      if (elems->ext_rates[i] & 0x80)
        basic_rates |= 1 << bit++;
  }

  return basic_rates;
}

static void log_reject(struct candidate *cand, const char *reason) {
  sae_debug(
      AMPE_DEBUG_FSM,
      "Mesh plink: rejecting action frame from " MACSTR " due to %s\n",
      MAC2STR(cand->peer_mac),
      reason);
}

static bool matches_local(
    struct mesh_node *mesh,
    struct candidate *cand,
    struct info_elems *elems) {
  char auth_algo = (mesh->conf->is_secure) ? MESH_CONFIG_AUTH_SAE : 0;

  if (!elems->mesh_id) {
    log_reject(cand, "missing mesh ID IE");
    return false;
  }

  if (!elems->mesh_config) {
    log_reject(cand, "missing mesh config IE");
    return false;
  }

  if (elems->mesh_config_len < 5) {
    log_reject(cand, "invalid mesh config IE");
    return false;
  }

  if (elems->mesh_id_len != mesh->conf->meshid_len ||
      memcmp(elems->mesh_id, mesh->conf->meshid, mesh->conf->meshid_len)) {
    log_reject(cand, "mesh ID does not match");
    return false;
  }

  if (elems->mesh_config[0] != MESH_CONFIG_PP_HWMP) {
    log_reject(cand, "mismatched path protocol");
    return false;
  }

  if (elems->mesh_config[1] != MESH_CONFIG_PM_ALM) {
    log_reject(cand, "mismatched link metric");
    return false;
  }

  if (elems->mesh_config[2] != MESH_CONFIG_CC_NONE) {
    log_reject(cand, "mismatched congestion control");
    return false;
  }

  if (elems->mesh_config[3] != MESH_CONFIG_SP_NEIGHBOR_OFFSET) {
    log_reject(cand, "mismatched sync protocol");
    return false;
  }

  if (elems->mesh_config[4] != auth_algo) {
    log_reject(cand, "mismatched auth algo");
    return false;
  }

  return true;
}

void ampe_set_peer_ies(struct candidate *cand, struct info_elems *elems) {
  if (elems->sup_rates) {
    memcpy(cand->sup_rates, elems->sup_rates, elems->sup_rates_len);
    cand->sup_rates_len = elems->sup_rates_len;
    if (elems->ext_rates) {
      memcpy(
          cand->sup_rates + elems->sup_rates_len,
          elems->ext_rates,
          elems->ext_rates_len);
      cand->sup_rates_len += elems->ext_rates_len;
    }
  }

  if (elems->ht_cap) {
    if (cand->ht_cap)
        free(cand->ht_cap);
    cand->ht_cap = memdup(elems->ht_cap, elems->ht_cap_len);
  }

  if (elems->ht_info) {
    if (cand->ht_info)
        free(cand->ht_info);
    cand->ht_info = memdup(elems->ht_info, elems->ht_info_len);
  }

  if (elems->vht_cap) {
    if (cand->vht_cap)
        free(cand->vht_cap);
    cand->vht_cap = memdup(elems->vht_cap, elems->vht_cap_len);
  }

  if (elems->vht_info) {
    if (cand->vht_info)
        free(cand->vht_info);
    cand->vht_info = memdup(elems->vht_info, elems->vht_info_len);
  }

  cand->ch_width = ht_op_to_channel_width(cand->ht_info, cand->vht_info);
}

/**
 * process_ampe_frame - process an ampe frame
 * @frame:     The full frame
 * @len:       The full frame length
 * @me:        The MAC address of the local interface
 * @cookie:    Opaque cookie that will be returned to the caller along with
 *             frames to be transmitted.
 *
 * Returns 0 unless something really horrible happened.  In other words, even
 * the frame could not be processed or it was corrupted, the function still
 * returns 0.
 */
int process_ampe_frame(
    struct ieee80211_mgmt_frame *mgmt,
    int len,
    unsigned char *me,
    void *cookie) {
  struct info_elems elems;
  struct info_elems our_elems;
  unsigned char ftype;
  struct candidate *cand = NULL;
  enum plink_event event;
  unsigned char ie_len = 0;
  unsigned short plid = 0, llid = 0;
  unsigned char *ies;
  unsigned short ies_len;
  size_t pmkid_len;

#define FAKE_LOSS_PROBABILITY 0
#if (FAKE_LOSS_PROBABILITY > 0)
  do {
    unsigned short dice;
    dice = RAND_bytes((unsigned char *)&dice, sizeof(dice));
    if ((dice % 100) < FAKE_LOSS_PROBABILITY) {
      sae_debug(AMPE_DEBUG_FSM, "Frame dropped\n");
      return 0;
    }
  } while (0);
#endif

  /* management header, category, action code, mesh id and peering mgmt*/
  if (len < 24 + 1 + 1 + 2 + 2)
    return 0;

  ies = start_of_ies(mgmt, len, &ies_len);
  parse_ies(ies, ies_len, &elems);
  if (!elems.mesh_peering) {
    sae_debug(AMPE_DEBUG_FSM, "Mesh plink: missing necessary peer link ie\n");
    return 0;
  }

  ftype = mgmt->action.action_code;
  ie_len = elems.mesh_peering_len;

  pmkid_len = ampe_conf.mesh->conf->is_secure ? sizeof(cand->pmkid) : 0;

  if ((ftype == PLINK_OPEN && ie_len != 4 + pmkid_len) ||
      (ftype == PLINK_CONFIRM && ie_len != 6 + pmkid_len) ||
      (ftype == PLINK_CLOSE && ie_len != 6 + pmkid_len &&
       ie_len != 8 + pmkid_len)) {
    sae_debug(
        AMPE_DEBUG_FSM,
        "Mesh plink: incorrect plink ie length %d %d\n",
        ftype,
        ie_len);
    return 0;
  }

  if (ftype != PLINK_CLOSE && (!elems.mesh_id || !elems.mesh_config)) {
    sae_debug(
        AMPE_DEBUG_FSM,
        "Mesh plink: missing necessary ie %p %p\n",
        elems.mesh_id,
        elems.mesh_config);
    return 0;
  }

  /* Note the lines below are correct, the llid in the frame is the plid
   * from the point of view of this host.
   */
  memcpy(&plid, PLINK_GET_LLID(elems.mesh_peering), 2);
  if (ftype == PLINK_CONFIRM || (ftype == PLINK_CLOSE && ie_len == 10))
    memcpy(&llid, PLINK_GET_PLID(elems.mesh_peering), 2);

  /* match BSSBasicRateSet*/
  parse_ies(sta_fixed_ies, sta_fixed_ies_len, &our_elems);
  if (ftype != PLINK_CLOSE &&
      get_basic_rates(&our_elems) != get_basic_rates(&elems)) {
    sae_debug(AMPE_DEBUG_FSM, "mesh plink: mismatched BSSBasicRateSet!\n");
    return 0;
  }

  /* require authed peers if secure mesh */
  if (ampe_conf.mesh->conf->is_secure) {
    /* "1" here means only get peers in SAE_ACCEPTED */
    if ((cand = find_peer(mgmt->sa, 1)) == NULL) {
      sae_debug(
          AMPE_DEBUG_FSM,
          "Mesh plink: plink open from unauthed peer " MACSTR "\n",
          MAC2STR(mgmt->sa));
      return 0;
    }
  } else {
    /*
     * In open mesh, there's no auth stage, so we create the station
     * when the first mgmt frame or beacon is received.  Do that now
     * if we haven't already and this is a plink open frame.
     */
    cand = find_peer(mgmt->sa, 0);
    if (!cand) {
      if (ftype != PLINK_OPEN) {
        sae_debug(
            AMPE_DEBUG_FSM,
            "Mesh plink: ignoring non-open frame from neighbor " MACSTR "\n",
            MAC2STR(mgmt->sa));
        return 0;
      }

      cand = create_candidate(mgmt->sa, me, 0, cookie);
      if (!cand) {
        sae_debug(
            AMPE_DEBUG_FSM,
            "Mesh plink: could not create new peer " MACSTR "\n",
            MAC2STR(mgmt->sa));
        return 0;
      }
    }
  }

  if (cand->my_lid == 0)
    peer_ampe_init(&ampe_conf, cand, cookie);

  ampe_set_peer_ies(cand, &elems);

  if (!protection_is_valid(cand, mgmt, len, &elems))
    return 0;

  cand->cookie = cookie;

  if (cand->link_state == PLINK_BLOCKED) {
    return 0;
  }

  /* Now we will figure out the appropriate event... */
  event = PLINK_UNDEFINED;

  switch (ftype) {
    case PLINK_OPEN:
      if (!matches_local(ampe_conf.mesh, cand, &elems))
        event = OPN_RJCT;
      else if (!plink_free_count(ampe_conf.mesh)) {
        log_reject(cand, "no free peer links");
        event = REQ_RJCT;
      } else if (cand->peer_lid && cand->peer_lid != plid) {
        log_reject(cand, "invalid peer link id");
        event = REQ_RJCT;
      } else {
        cand->peer_lid = plid;
        event = OPN_ACPT;
      }
      break;
    case PLINK_CONFIRM:
      if (!matches_local(ampe_conf.mesh, cand, &elems))
        event = CNF_RJCT;
      else if (!plink_free_count(ampe_conf.mesh)) {
        log_reject(cand, "no free peer links");
        event = REQ_RJCT;
      } else if (cand->my_lid != llid) {
        log_reject(cand, "invalid local link id");
        event = REQ_RJCT;
      } else if (cand->peer_lid != plid) {
        log_reject(cand, "invalid peer link id");
        event = REQ_RJCT;
      } else
        event = CNF_ACPT;
      break;
    case PLINK_CLOSE:
      if (cand->link_state == PLINK_ESTAB)
        /* Do not check for llid or plid. This does not
         * follow the standard but since multiple plinks
         * per cand are not supported, it is necessary in
         * order to avoid a livelock when MP A sees an
         * establish peer link to MP B but MP B does not
         * see it. This can be caused by a timeout in
         * B's peer link establishment or B beign
         * restarted.
         */
        event = CLS_ACPT;
      else if (cand->peer_lid != plid)
        event = CLS_IGNR;
      else if (ie_len == 7 && cand->my_lid != llid)
        event = CLS_IGNR;
      else
        event = CLS_ACPT;
      break;
    default:
      sae_debug(AMPE_DEBUG_FSM, "Mesh plink: unknown frame subtype\n");
      return 0;
  }

  sae_debug(
      AMPE_DEBUG_FSM,
      "Mesh plink peer=" MACSTR " state=%s llid=%d plid=%d event=%s\n",
      MAC2STR(mgmt->sa),
      mpl_states[cand->link_state],
      le16toh(cand->my_lid),
      le16toh(cand->peer_lid),
      mpl_events[event]);

  fsm_step(cand, event);

  return 0;
}

static bool check_callbacks(struct ampe_cb *callbacks) {
  bool valid = callbacks != NULL;
  valid = valid && callbacks->meshd_write_mgmt != NULL;
  valid = valid && callbacks->meshd_set_mesh_conf != NULL;
  valid = valid && callbacks->set_plink_state != NULL;
  valid = valid && callbacks->estab_peer_link != NULL;
  return valid;
}

int ampe_initialize(struct mesh_node *mesh, struct ampe_cb *callbacks) {
  int sup_rates_len;

  if (!check_callbacks(callbacks))
    return -1;

  cb = callbacks;

  /* TODO: move these to a config file */
  ampe_conf.retry_timeout_ms = 1000;
  ampe_conf.holding_timeout_ms = 10000;
  ampe_conf.confirm_timeout_ms = 1000;
  ampe_conf.max_retries = 10;
  ampe_conf.mesh = mesh;

  if (mesh->conf->is_secure) {
    RAND_bytes(mgtk_tx, 16);
    sae_hexdump(AMPE_DEBUG_KEYS, "mgtk: ", mgtk_tx, sizeof(mgtk_tx));
  }

  if (mesh->conf->pmf) {
    RAND_bytes(mesh->igtk_tx, 16);
    mesh->igtk_keyid = 4;
    memset(mesh->igtk_ipn, 0, sizeof(mesh->igtk_ipn));
    sae_hexdump(
        AMPE_DEBUG_KEYS, "igtk: ", mesh->igtk_tx, sizeof(mesh->igtk_tx));
  }

  /* We can do this because valid supported rates non null and the array is null
   * terminated */
  sup_rates_len = strnlen((char *)mesh->conf->rates, sizeof(mesh->conf->rates));
  if (sup_rates_len <= 8) {
    /*  rates fit into a the supported rates IE */
    sta_fixed_ies_len = 2 + sup_rates_len;
    sta_fixed_ies = malloc(sta_fixed_ies_len);
    *sta_fixed_ies = IEEE80211_EID_SUPPORTED_RATES;
    *(sta_fixed_ies + 1) = sup_rates_len;
    memcpy(sta_fixed_ies + 2, mesh->conf->rates, sup_rates_len);
  } else if (sup_rates_len < sizeof(mesh->conf->rates)) {
    /*  rates overflow onto the extended supported rates IE */
    sta_fixed_ies_len = 4 + sup_rates_len;
    sta_fixed_ies = malloc(sta_fixed_ies_len);
    *sta_fixed_ies = IEEE80211_EID_SUPPORTED_RATES;
    *(sta_fixed_ies + 1) = 8;
    memcpy(sta_fixed_ies + 2, mesh->conf->rates, 8);
    *(sta_fixed_ies + 10) = IEEE80211_EID_EXTENDED_SUP_RATES;
    *(sta_fixed_ies + 11) = sup_rates_len - 8;
    memcpy(sta_fixed_ies + 12, mesh->conf->rates + 8, sup_rates_len - 8);
  } else {
    sae_debug(SAE_DEBUG_ERR, "mesh->conf->rates should be null-terminated");
    return -1;
  }

  sae_hexdump(
      MESHD_DEBUG,
      "Fixed Information Elements in this STA",
      sta_fixed_ies,
      sta_fixed_ies_len);
  return 0;
}
