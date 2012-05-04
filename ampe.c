/* vim: et ts=4 sw=4
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
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/queue.h>
#include <net/if.h>
#include <assert.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include "service.h"
#include "common.h"
#include "ieee802_11.h"
#include "os_glue.h"
#include "sae.h"
#include "ampe.h"
#include "crypto/siv.h"
#include "peers.h"

/* Peer link cancel reasons */
#define MESH_LINK_CANCELLED                     52
#define MESH_MAX_NEIGHBORS                      53
#define MESH_CAPABILITY_POLICY_VIOLATION        54
#define MESH_CLOSE_RCVD                         55
#define MESH_MAX_RETRIES                        56
#define MESH_CONFIRM_TIMEOUT                    57
#define MESH_SECURITY_INVALID_GTK               58
#define MESH_SECURITY_INCONSISTENT_PARAMS       59
#define MESH_SECURITY_INVALID_CAPABILITY        60

static const unsigned char akm_suite_selector[4] = { 0x0, 0xf, 0xac, 0x8 };     /*  SAE  */
static const unsigned char pw_suite_selector[4] = { 0x0, 0xf, 0xac, 0x4 };     /*  CCMP  */
static const unsigned char null_nonce[32] = { 0 };

/* global configuration data */
static struct ampe_config ampe_conf;

/*  For debugging use */
static const char *mplstates[] = {
    [PLINK_LISTEN] = "LISTEN",
    [PLINK_OPN_SNT] = "OPN-SNT",
    [PLINK_OPN_RCVD] = "OPN-RCVD",
    [PLINK_CNF_RCVD] = "CNF_RCVD",
    [PLINK_ESTAB] = "ESTAB",
    [PLINK_HOLDING] = "HOLDING",
    [PLINK_BLOCKED] = "BLOCKED"
};


static int plink_frame_tx(struct candidate *cand, enum
        plink_action_code action, unsigned short reason);

/**
 * fsm_restart - restart a mesh peer link finite state machine
 *
 * @cand: mesh peer link to restart
 *
 * */
static inline void fsm_restart(struct candidate *cand)
{
    cand->link_state = PLINK_LISTEN;
    cand->my_lid = cand->peer_lid = cand->reason = 0;
    cand->retries = 0;
}

extern service_context srvctx;

enum plink_event {
        PLINK_UNDEFINED,
        OPN_ACPT,
        OPN_RJCT,
        OPN_IGNR,
        CNF_ACPT,
        CNF_RJCT,
        CNF_IGNR,
        CLS_ACPT,
        CLS_IGNR
};

static int plink_free_count() {
    sae_debug(AMPE_DEBUG_FSM, "TODO: return available peer link slots\n");
    return 99;
}

static inline u8* start_of_ies(struct ieee80211_mgmt_frame *frame,
    int len, u16 *ie_len)
{
    int offset=0;
    switch(frame->action.action_code) {
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

static void derive_aek(struct candidate *cand)
{
    unsigned char context[AES_BLOCK_SIZE];

    memcpy(context, akm_suite_selector, 4);
    if (memcmp(cand->my_mac, cand->peer_mac, ETH_ALEN) < 0) {
        memcpy(context + 4, cand->my_mac, ETH_ALEN);
        memcpy(context + 10, cand->peer_mac, ETH_ALEN);
    } else {
        memcpy(context + 4, cand->peer_mac, ETH_ALEN);
        memcpy(context + 10, cand->my_mac, ETH_ALEN);
    }

    prf(cand->pmk, SHA256_DIGEST_LENGTH,
        (unsigned char *)"AEK Derivation", strlen("AEK Derivation"),
        context, sizeof(context),
        cand->aek, SHA256_DIGEST_LENGTH * 8);

    sae_hexdump(AMPE_DEBUG_KEYS, "aek context: ", context, sizeof(context));
    sae_hexdump(AMPE_DEBUG_KEYS, "aek: ", cand->aek, sizeof(cand->aek));
}

/* determine and set the correct ht operation mode for all established peers
 * according to 802.11mb 9.23.3. Return MESH_CONF_CHANGED_HT bit if a new
 * operation mode was selected */
static uint32_t mesh_set_ht_op_mode(struct mesh_node *mesh)
{
    struct candidate *peer;
    uint32_t changed = 0;
    unsigned int ht_opmode;
    bool no_ht = false, ht20 = false;

    if (mesh->conf->channel_type == NL80211_CHAN_NO_HT)
        return 0;

    for_each_peer(peer) {
        if (peer->link_state != PLINK_ESTAB)
            continue;

        switch (peer->ch_type) {
        case NL80211_CHAN_NO_HT:
            no_ht = true;
            goto out;
        case NL80211_CHAN_HT20:
            ht20 = true;
        default:
            break;
        }
    }

out:
    if (no_ht)
        ht_opmode = IEEE80211_HT_OP_MODE_PROTECTION_NONHT_MIXED;
    else if (ht20 && mesh->conf->channel_type > NL80211_CHAN_HT20)
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

static void peer_ampe_init(struct ampe_config *aconf,
                           struct candidate *cand, unsigned char *me, void *cookie)
{
	le16 llid;

    assert(cand && me);

    RAND_bytes((unsigned char *) &llid, 2);
    RAND_bytes(cand->my_nonce, sizeof(cand->my_nonce));
    cand->cookie = cookie;
	cand->my_lid = llid;
	cand->peer_lid = 0;
	cand->link_state = PLINK_LISTEN;
    cand->timeout = aconf->retry_timeout_ms;
    cand->conf = aconf;
    derive_aek(cand);
    siv_init(&cand->sivctx, cand->aek, SIV_256);
	return;
}

static void plink_timer(timerid id, void *data)
{
	__le16 reason;
    struct candidate *cand;

	cand = (struct candidate *)data;

    assert(cand);

    sae_debug(AMPE_DEBUG_FSM, "Mesh plink timer for " MACSTR
            " fired on state %s\n", MAC2STR(cand->peer_mac),
		    mplstates[(cand->link_state > PLINK_BLOCKED) ? PLINK_UNDEFINED : cand->link_state]);

	reason = 0;

	switch (cand->link_state) {
	case PLINK_OPN_RCVD:
	case PLINK_OPN_SNT:
		/* retry timer */
        sae_debug(AMPE_DEBUG_FSM, "Mesh plink:retries %d of %d\n", cand->retries,
                  cand->conf->max_retries);
		if (cand->retries < cand->conf->max_retries) {
			unsigned int rand;
            sae_debug(AMPE_DEBUG_FSM, "Mesh plink for " MACSTR
                    " (retry, timeout): %d %d\n", MAC2STR(cand->peer_mac),
                    cand->retries, cand->timeout);
			RAND_bytes((unsigned char *) &rand, sizeof(rand));
            if (!cand->timeout) {
                cand->timeout = cand->conf->retry_timeout_ms;
                sae_debug(AMPE_DEBUG_ERR, "WARN: cand " MACSTR
                    " had a timeout of 0ms.  Reset to %d\n",
                    MAC2STR(cand->peer_mac),cand->timeout);
            }
            cand->timeout += rand % cand->timeout;
			++cand->retries;
            cand->t2 = srv_add_timeout(srvctx,
                    SRV_MSEC(cand->timeout), plink_timer,
                    cand);
			plink_frame_tx(cand, PLINK_OPEN, 0);
			break;
		}
		reason = htole16(MESH_MAX_RETRIES);
		/* fall through on else */
	case PLINK_CNF_RCVD:
		/* confirm timer */
		if (!reason)
			reason = htole16(MESH_CONFIRM_TIMEOUT);
		cand->link_state = PLINK_HOLDING;
        cand->t2 = srv_add_timeout(srvctx,
                    SRV_MSEC(cand->conf->holding_timeout_ms), plink_timer,
                    cand);
		plink_frame_tx(cand, PLINK_CLOSE, reason);
		break;
	case PLINK_HOLDING:
		/* holding timer */
		fsm_restart(cand);
		break;
	default:
        sae_debug(AMPE_DEBUG_FSM, "Timeout for peer " MACSTR
                " in state %d\n", MAC2STR(cand->peer_mac),
                cand->link_state);
		break;
	}
}


/**
 * protect_frame - add in-place the MIC and the (encrypted) AMPE ie to a frame
 * @cand:       The candidate this frame is destined for
 * @mgmt:       The frame, populated with all the information elements  up to where the MIC information element should go
 * @mic_start:  Pointer to where the mic and AMPE ies are to be written.  Should point to the start of the IE, not the IE body.
 * @len:        On input, the total buffer size that contains this frame.  On output, the actual lenght of the frame
 *              including the two information elements added by this function.
 *
 * Returns: The zero on success, or some error.
 */
static int protect_frame(struct candidate *cand, struct ieee80211_mgmt_frame *mgmt, unsigned char *mic_start, int *len)
{
    unsigned char *clear_ampe_ie;
    unsigned char *ie;
    unsigned short cat_to_mic_len;

    assert(mic_start && cand && mgmt && len);

#define MIC_IE_BODY_SIZE     AES_BLOCK_SIZE

    if (mic_start + MIC_IE_BODY_SIZE + 2 + sizeof(struct ampe_ie) + 2 - (unsigned char *) mgmt > *len) {
		sae_debug(AMPE_DEBUG_KEYS, "protect frame: buffer too small\n");
        return -EINVAL;
    }

    clear_ampe_ie = malloc(sizeof(struct ampe_ie) + 2);
    if (!clear_ampe_ie) {
		sae_debug(AMPE_DEBUG_KEYS, "protect frame: out of memory\n");
        return -ENOMEM;
    }

    /*  IE: AMPE */
    ie = clear_ampe_ie;
    *ie++ = IEEE80211_EID_AMPE;
    *ie++ = sizeof(struct ampe_ie);
    memcpy(ie, pw_suite_selector, 4);
    ie += 4;
    memcpy(ie, cand->my_nonce, 32);
    ie += 32;
    memcpy(ie, cand->peer_nonce, 32);
    ie += 32;
    memcpy(ie, mgtk_tx, 16);
    ie += 16;
    memset(ie, 0, 8);           /*  TODO: Populate Key RSC */
    ie += 8;
    memset(ie, 0xff, 4);        /*  expire in 13 decades or so */
    ie += 4;

    /* IE: MIC */
    ie = mic_start;
    *ie++ = IEEE80211_EID_MIC;
    *ie++ = MIC_IE_BODY_SIZE;

    cat_to_mic_len = mic_start - (unsigned char *) &mgmt->action;
    siv_encrypt(&cand->sivctx, clear_ampe_ie, ie + MIC_IE_BODY_SIZE,
            sizeof(struct ampe_ie) + 2,
            ie, 3,
            cand->my_mac, ETH_ALEN,
            cand->peer_mac, ETH_ALEN,
            &mgmt->action, cat_to_mic_len);

    *len = mic_start - (unsigned char *) mgmt + sizeof(struct ampe_ie) + 2 + MIC_IE_BODY_SIZE + 2;

    sae_debug(AMPE_DEBUG_KEYS, "Protecting frame from " MACSTR " to " MACSTR "\n",
            MAC2STR(cand->my_mac), MAC2STR(cand->peer_mac));
    sae_debug(AMPE_DEBUG_KEYS, "Checking tricky lengths of protected frame %d, %d\n",
            cat_to_mic_len, sizeof(struct ampe_ie) + 2);

    sae_hexdump(AMPE_DEBUG_KEYS, "SIV- Put AAD[3]: ", (unsigned char *) &mgmt->action, cat_to_mic_len);

    free(clear_ampe_ie);

    return 0;
}

static int check_frame_protection(struct candidate *cand, struct ieee80211_mgmt_frame *mgmt, int len, struct info_elems *elems)
{
    unsigned char *clear_ampe_ie;
    struct info_elems ies_parsed;
    unsigned short ampe_ie_len, cat_to_mic_len;
    int r;
    unsigned int* key_expiration_p;

    assert(len && cand && mgmt);

    clear_ampe_ie = malloc(sizeof(struct ampe_ie) + 2);
    if (!clear_ampe_ie) {
		sae_debug(AMPE_DEBUG_KEYS, "Verify frame: out of memory\n");
        return -1;
    }

    if (!elems->mic || elems->mic_len != MIC_IE_BODY_SIZE) {
		sae_debug(AMPE_DEBUG_KEYS, "Verify frame: invalid MIC\n");
        return -1;
    }

    /*
     *  ampe_ie_len is the length of the ciphertext (the encrypted
     *  AMPE IE) and it needs to be inferred from the total frame
     *  size
     */
    ampe_ie_len = len -
                (elems->mic + elems->mic_len - (unsigned char *)mgmt);
    /*
     *  cat_to_mic_len is the length of the contents of the frame
     *  from the category (inclusive) to the mic (exclusive)
     */
    cat_to_mic_len = elems->mic - 2 - (unsigned char *) &mgmt->action;
    r = siv_decrypt(&cand->sivctx, elems->mic + elems->mic_len,
            clear_ampe_ie,
            ampe_ie_len,
            elems->mic, 3,
            cand->peer_mac, ETH_ALEN,
            cand->my_mac, ETH_ALEN,
            &mgmt->action, cat_to_mic_len);

    sae_debug(AMPE_DEBUG_KEYS, "Checking protection to " MACSTR " from " MACSTR "\n",
            MAC2STR(cand->my_mac), MAC2STR(cand->peer_mac));

    sae_debug(AMPE_DEBUG_KEYS, "Len checking cat-to-mic len:%d ampe ie full length: %d\n",
            cat_to_mic_len, ampe_ie_len);

    sae_hexdump(AMPE_DEBUG_KEYS, "SIV- Got AAD[3]: ", (unsigned char *) &mgmt->action,
            cat_to_mic_len);

    if (r != 1) {
        sae_debug(AMPE_DEBUG_KEYS, "Protection check failed\n");
        return -1;
    }

    sae_hexdump(AMPE_DEBUG_KEYS, "AMPE IE: ", clear_ampe_ie, ampe_ie_len);

    parse_ies(clear_ampe_ie, ampe_ie_len, &ies_parsed);

    if (memcmp(ies_parsed.ampe->peer_nonce, null_nonce, 32) != 0 &&
        memcmp(ies_parsed.ampe->peer_nonce, cand->my_nonce, 32) != 0) {
        sae_hexdump(AMPE_DEBUG_KEYS, "IE peer_nonce ", ies_parsed.ampe->peer_nonce, 32);
        sae_debug(AMPE_DEBUG_KEYS, "Unexpected nonce\n");
        return -1;
    }
    memcpy(cand->peer_nonce, ies_parsed.ampe->local_nonce, 32);
    memcpy(cand->mgtk, ies_parsed.ampe->mgtk, sizeof(cand->mgtk));
    sae_hexdump(AMPE_DEBUG_KEYS, "Received mgtk: ", cand->mgtk, sizeof(cand->mgtk));
    key_expiration_p = (unsigned int *)ies_parsed.ampe->key_expiration;
    cand->mgtk_expiration = le32toh(*key_expiration_p);
    free(clear_ampe_ie);
    return -1;
#undef MIC_IE_BODY_SIZE
}

static int plink_frame_tx(struct candidate *cand, enum plink_action_code action,
                          unsigned short reason)
{
        unsigned char *buf;
        struct ieee80211_mgmt_frame *mgmt;
        struct mesh_node *mesh = cand->conf->mesh;
        struct ieee80211_supported_band *sband = &mesh->bands[mesh->band];
        struct ht_cap_ie *ht_cap;
        struct ht_op_ie *ht_op;
        unsigned char ie_len;
        int len;
        unsigned char *ies;
        unsigned char *pos;
        u16 peering_proto = htole16(0x0001);    /* AMPE */

        assert(cand);

#define LARGE_FRAME 1500;
        len = LARGE_FRAME;
        buf = calloc(1, len);
#undef LARGE_FRAME
        if (!buf)
                return -1;

        sae_debug(AMPE_DEBUG_FSM, "Mesh plink: Sending plink action %d\n", action);

        mgmt = (struct ieee80211_mgmt_frame *) buf;
        mgmt->frame_control = htole16((IEEE802_11_FC_TYPE_MGMT << 2 |
                                    IEEE802_11_FC_STYPE_ACTION << 4));

        memcpy(mgmt->da, cand->peer_mac, ETH_ALEN);
        memcpy(mgmt->sa, cand->my_mac, ETH_ALEN);
        memcpy(mgmt->bssid, cand->my_mac, ETH_ALEN);
        mgmt->action.category = IEEE80211_CATEGORY_SELF_PROTECTED;
        mgmt->action.action_code = action;
        pos = mgmt->action.u.var8;

        if (action != PLINK_CLOSE) {
            /* capability info */
            *pos++ = 0x10;       /* securitu */
            *pos++ = 0;
            if (action == PLINK_CONFIRM) {
                /* AID */
                memset(pos, 0, 2);
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
        memcpy((char *) ies, mesh->conf->meshid, mesh->conf->meshid_len);
        ies += mesh->conf->meshid_len;

        /* IE: mesh config */
        *ies++ = IEEE80211_EID_MESH_CONFIG;
        *ies++ = 8;
        /*  TODO: IIRC all the defaults are 0. Double check */
        memset(ies, 0, 8);
        ies += 8;

        ie_len = 4 + 16;        /* min. + PMKID */
        /* IE: Mesh Peering Management element */
        switch (action) {
            case PLINK_OPEN:
                break;
            case PLINK_CONFIRM:
                ie_len += 2;
                break;
            case PLINK_CLOSE:
                if (&cand->peer_lid) {
                    ie_len += 2;
                }
                ie_len += 2;	/* reason code */
                break;
            default:
                return -EINVAL;
        }

        *ies++ = IEEE80211_EID_MESH_PEERING;
        *ies++ = ie_len;
        memcpy(ies, &peering_proto, 2);
        ies += 2;
        memcpy(ies, &cand->my_lid, 2);
        ies += 2;
        if (cand->peer_lid && (action != PLINK_OPEN)) {
            memcpy(ies, &cand->peer_lid, 2);
            ies += 2;
        }
        if (action == PLINK_CLOSE) {
            memcpy(ies, &cand->reason, 2);
            ies += 2;
        }
        memcpy(ies, cand->pmkid, sizeof(cand->pmkid));
        ies += sizeof(cand->pmkid);

        if (mesh->conf->channel_type != NL80211_CHAN_NO_HT &&
            sband->ht_cap.ht_supported) {

            /* HT IEs */
            *ies++ = IEEE80211_EID_HT_CAPABILITY;
            *ies++ = sizeof(struct ht_cap_ie);
            ht_cap = (struct ht_cap_ie *) ies;
            ht_cap->cap_info = htole16(sband->ht_cap.cap);
            ht_cap->ampdu_params_info = sband->ht_cap.ampdu_factor |
                                        (sband->ht_cap.ampdu_density << 2);
            memcpy(&ht_cap->mcs, &sband->ht_cap.mcs, sizeof(struct mcs_info));
            /* mac80211 apparently ignores the rest */
            ies += sizeof(*ht_cap);

            *ies++ = IEEE80211_EID_HT_OPERATION;
            *ies++ = sizeof(struct ht_op_ie);
            ht_op = (struct ht_op_ie *) ies;
            ht_op->primary_chan = mesh->conf->channel;
            switch (mesh->conf->channel_type) {
            case NL80211_CHAN_HT40MINUS:
                ht_op->ht_param = IEEE80211_HT_PARAM_CHA_SEC_BELOW;
                break;
            case NL80211_CHAN_HT40PLUS:
                ht_op->ht_param = IEEE80211_HT_PARAM_CHA_SEC_ABOVE;
                break;
            case NL80211_CHAN_HT20:
            default:
                ht_op->ht_param = IEEE80211_HT_PARAM_CHA_SEC_NONE;
                break;
            }
            if (sband->ht_cap.cap & IEEE80211_HT_CAP_SUP_WIDTH_20_40 &&
                mesh->conf->channel_type > NL80211_CHAN_HT20)
                    ht_op->ht_param |= IEEE80211_HT_PARAM_CHAN_WIDTH_ANY;

            ht_op->operation_mode = htole16(mesh->conf->ht_prot_mode);
            memset(ht_op->basic_set, 0, 16);
            ht_op->basic_set[0] = 0xff; /* mandatory HT phy rates */
            ies += sizeof(*ht_op);
        }

        /* IE: Add MIC and encrypted AMPE */
        if (protect_frame(cand, (struct ieee80211_mgmt_frame *)buf, ies, &len) < 0)
            sae_debug(SAE_DEBUG_ERR, "Failed to protect frame\n");

        if (meshd_write_mgmt((char *)buf, len, cand->cookie) != len) {
            sae_debug(SAE_DEBUG_ERR, "can't send a peering "
                    "frame to " MACSTR "\n", MAC2STR(cand->peer_mac));
        }
        free(buf);
        return 0;
}

static void derive_mtk(struct candidate *cand)
{
    unsigned char context[84];
    unsigned char *p;

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

    prf(cand->pmk, SHA256_DIGEST_LENGTH,
        (unsigned char *)"Temporal Key Derivation", strlen("Temporal Key Derivation"),
        context, sizeof(context),
        cand->mtk, 16 * 8);

    sae_hexdump(AMPE_DEBUG_KEYS, "mtk context: ", context, sizeof(context));
    sae_hexdump(AMPE_DEBUG_KEYS, "mtk: ", cand->mtk, sizeof(cand->mtk));
}


static void fsm_step(struct candidate *cand, enum plink_event event)
{
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
            cand->t2 = srv_add_timeout(srvctx, SRV_MSEC(cand->timeout), plink_timer, cand);
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
			reason = htole16(MESH_CAPABILITY_POLICY_VIOLATION);
		case CLS_ACPT:
			if (!reason)
				reason = htole16(MESH_CLOSE_RCVD);
			cand->reason = reason;
			cand->link_state = PLINK_HOLDING;
            cand->timeout = aconf->holding_timeout_ms;
            cand->t2 = srv_add_timeout(srvctx, SRV_MSEC(cand->timeout), plink_timer, cand);
			plink_frame_tx(cand, PLINK_CLOSE, reason);
			break;
		case OPN_ACPT:
			/* retry timer is left untouched */
			cand->link_state = PLINK_OPN_RCVD;
			plink_frame_tx(cand, PLINK_CONFIRM, 0);
			break;
		case CNF_ACPT:
			cand->link_state = PLINK_CNF_RCVD;
            cand->timeout = aconf->confirm_timeout_ms;
            cand->t2 = srv_add_timeout(srvctx, SRV_MSEC(cand->timeout), plink_timer, cand);
			break;
		default:
			break;
		}
		break;

	case PLINK_OPN_RCVD:
		switch (event) {
		case OPN_RJCT:
		case CNF_RJCT:
			reason = htole16(MESH_CAPABILITY_POLICY_VIOLATION);
		case CLS_ACPT:
			if (!reason)
				reason = htole16(MESH_CLOSE_RCVD);
			cand->reason = reason;
			cand->link_state = PLINK_HOLDING;
            cand->timeout = aconf->holding_timeout_ms;
            cand->t2 = srv_add_timeout(srvctx, SRV_MSEC(cand->timeout), plink_timer, cand);
			plink_frame_tx(cand, PLINK_CLOSE, reason);
			break;
		case OPN_ACPT:
			plink_frame_tx(cand, PLINK_CONFIRM, 0);
			break;
		case CNF_ACPT:
			//del_timer(&cand->plink_timer);
			cand->link_state = PLINK_ESTAB;
			//mesh_plink_inc_estab_count(sdata);
			//ieee80211_bss_info_change_notify(sdata, BSS_CHANGED_BEACON);
            derive_mtk(cand);
            estab_peer_link(cand->peer_mac,
                    cand->mtk, sizeof(cand->mtk),
                    cand->mgtk, sizeof(cand->mgtk),
                    cand->mgtk_expiration,
                    cand->sup_rates,
                    cand->sup_rates_len,
                    cand->cookie);
            changed |= mesh_set_ht_op_mode(cand->conf->mesh);
            sae_debug(AMPE_DEBUG_FSM, "mesh plink with "
                    MACSTR " established\n", MAC2STR(cand->peer_mac));
			break;
		default:
			break;
		}
		break;

	case PLINK_CNF_RCVD:
		switch (event) {
		case OPN_RJCT:
		case CNF_RJCT:
			reason = htole16(MESH_CAPABILITY_POLICY_VIOLATION);
		case CLS_ACPT:
			if (!reason)
				reason = htole16(MESH_CLOSE_RCVD);
			cand->reason = reason;
			cand->link_state = PLINK_HOLDING;
            cand->timeout = aconf->holding_timeout_ms;
            cand->t2 = srv_add_timeout(srvctx, SRV_MSEC(cand->timeout), plink_timer, cand);
			plink_frame_tx(cand, PLINK_CLOSE, reason);
			break;
		case OPN_ACPT:
			cand->link_state = PLINK_ESTAB;
            estab_peer_link(cand->peer_mac,
                    cand->mtk, sizeof(cand->mtk),
                    cand->mgtk, sizeof(cand->mgtk),
                    cand->mgtk_expiration, cand->sup_rates,
                    cand->sup_rates_len,
                    cand->cookie);
            changed |= mesh_set_ht_op_mode(cand->conf->mesh);
            //TODO: update the number of available peer "slots" in mesh config
			//mesh_plink_inc_estab_count(sdata);
			//ieee80211_bss_info_change_notify(sdata, BSS_CHANGED_BEACON);
			sae_debug(AMPE_DEBUG_FSM, "Mesh plink with "
                    MACSTR " ESTABLISHED\n", MAC2STR(cand->peer_mac));
			plink_frame_tx(cand, PLINK_CONFIRM, 0);
			break;
		default:
			break;
		}
		break;

	case PLINK_ESTAB:
		switch (event) {
		case CLS_ACPT:
			reason = htole16(MESH_CLOSE_RCVD);
			cand->reason = reason;
			cand->link_state = PLINK_HOLDING;
            cand->timeout = aconf->holding_timeout_ms;
            cand->t2 = srv_add_timeout(srvctx, SRV_MSEC(cand->timeout), plink_timer, cand);
            changed |= mesh_set_ht_op_mode(cand->conf->mesh);
            //TODO: update the number of available peer "slots" in mesh config
			//if (deactivated)
		    //	ieee80211_bss_info_change_notify(sdata, BSS_CHANGED_BEACON);
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
			//if (del_timer(&cand->plink_timer))
			//	cand->ignore_plink_timer = 1;
			fsm_restart(cand);
			break;
		case OPN_ACPT:
		case CNF_ACPT:
		case OPN_RJCT:
		case CNF_RJCT:
			reason = cand->reason;
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
        meshd_set_mesh_conf(cand->conf->mesh, changed);
}

#define PLINK_GET_LLID(p) (p + 2)
#define PLINK_GET_PLID(p) (p + 4)


/**
 * start_peer_link - attempt to establish a peer link
 * @peer:      MAC address of the candidate peer
 * @me:        The MAC address of the local interface
 * @cookie:    Opaque cookie that will be returned to the caller along with
 *             frames to be transmitted.
 *
 * Returns 0 or a negative error.
 */
int start_peer_link(unsigned char *peer_mac, unsigned char *me, void *cookie)
{
    struct candidate *cand;

    assert(peer_mac && me);

 	if ((cand = find_peer(peer_mac, 0)) == NULL) {
        sae_debug(AMPE_DEBUG_FSM, "Mesh plink: Attempt to peer with "
                " non-authed peer\n");
            return -EPERM;
	}

    peer_ampe_init(&ampe_conf, cand, me, cookie);
	cand->link_state = PLINK_OPN_SNT;
    cand->t2 = srv_add_timeout(srvctx, SRV_MSEC(cand->timeout), plink_timer, cand);

	sae_debug(AMPE_DEBUG_FSM, "Mesh plink: starting establishment "
            "with " MACSTR "\n", MAC2STR(peer_mac));


	return plink_frame_tx(cand, PLINK_OPEN, 0);
}

static uint32_t get_basic_rates(struct info_elems *elems)
{
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
int process_ampe_frame(struct ieee80211_mgmt_frame *mgmt, int len,
                        unsigned char *me, void *cookie)
{
    struct info_elems elems;
    struct info_elems our_elems;
    unsigned char ftype;
	struct candidate *cand = NULL;
	enum plink_event event;
	unsigned char ie_len = 0;
	unsigned short plid = 0, llid = 0;
    unsigned char *ies;
    unsigned short ies_len;

#define FAKE_LOSS_PROBABILITY 0
#if (FAKE_LOSS_PROBABILITY > 0)
    do {
        unsigned short dice;
        dice = RAND_bytes((unsigned char *) &dice, sizeof(dice));
        if ((dice % 100) < FAKE_LOSS_PROBABILITY) {
            sae_debug(AMPE_DEBUG_FSM, "Frame dropped\n");
            return 0;
        }
    } while (0);
#endif

	/* management header, category, action code, mesh id and peering mgmt*/
	if (len < 24 + 1 + 1 + 2 + 2)
		return 0;

	//if (is_multicast_ether_addr(mgmt->da)) {
	//	sae_debug(AMPE_DEBUG_FSM, "Mesh plink: ignore frame to multicast address");
	//	return 0;
	//}


	ies = start_of_ies(mgmt, len, &ies_len);
	parse_ies(ies, ies_len, &elems);
	if (!elems.mesh_peering) {  // || !elems.rsn) {
		sae_debug(AMPE_DEBUG_FSM, "Mesh plink: missing necessary peer link ie\n");
		return 0;
	}

	ftype = mgmt->action.action_code;
	ie_len = elems.mesh_peering_len;

	if ((ftype == PLINK_OPEN && ie_len != 20) ||
	    (ftype == PLINK_CONFIRM && ie_len != 22) ||
	    (ftype == PLINK_CLOSE && ie_len != 22 && ie_len != 24)) {
		sae_debug(AMPE_DEBUG_FSM, "Mesh plink: incorrect plink ie length %d %d\n",
		    ftype, ie_len);
		return 0;
	}

    if (ftype != PLINK_CLOSE && (!elems.mesh_id || !elems.mesh_config)) {
        sae_debug(AMPE_DEBUG_FSM, "Mesh plink: missing necessary ie %p %p\n", elems.mesh_id, elems.mesh_config);
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
    if (get_basic_rates(&our_elems) != get_basic_rates(&elems)) {
        sae_debug(AMPE_DEBUG_FSM, "mesh plink: mismatched BSSBasicRateSet!\n");
        return 0;
    }

    if ((cand = find_peer(mgmt->sa, 0)) == NULL) {
		sae_debug(AMPE_DEBUG_FSM, "Mesh plink: plink open from unauthed peer\n");
        return 0;
    }

    if (cand->my_lid == 0)
        peer_ampe_init(&ampe_conf, cand, me, cookie);

    if (elems.sup_rates) {
        memcpy(cand->sup_rates, elems.sup_rates,
                elems.sup_rates_len);
        cand->sup_rates_len = elems.sup_rates_len;
        if (elems.ext_rates) {
            memcpy(cand->sup_rates + elems.sup_rates_len,
                    elems.ext_rates, elems.ext_rates_len);
            cand->sup_rates_len += elems.ext_rates_len;
        }
    }

    check_frame_protection(cand, mgmt, len, &elems);

    cand->cookie = cookie;



	if (cand->link_state == PLINK_BLOCKED) {
		return 0;
	}

	/* Now we will figure out the appropriate event... */
	event = PLINK_UNDEFINED;
//	if (ftype != PLINK_CLOSE && (!mesh_matches_local(&elems, sdata))) {
	if (ftype != PLINK_CLOSE) {
		switch (ftype) {
		case PLINK_OPEN:
			event = OPN_RJCT;
			break;
		case PLINK_CONFIRM:
			event = CNF_RJCT;
			break;
		case PLINK_CLOSE:
			break;
		}
	}

    switch (ftype) {
    case PLINK_OPEN:
        if (!plink_free_count() ||
            (cand->peer_lid && cand->peer_lid != plid))
            event = OPN_IGNR;
        else {
            cand->peer_lid = plid;
            event = OPN_ACPT;
        }
        break;
    case PLINK_CONFIRM:
        if (!plink_free_count() ||
            (cand->my_lid != llid || cand->peer_lid != plid))
            event = CNF_IGNR;
        else
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

	sae_debug(AMPE_DEBUG_FSM, "Mesh plink (peer, state, llid, plid, event): " MACSTR " %s %d %d %d\n",
		MAC2STR(mgmt->sa), mplstates[cand->link_state],
		le16toh(cand->my_lid), le16toh(cand->peer_lid),
		event);

    fsm_step(cand, event);

    return 0;
}

int ampe_initialize(struct mesh_node *mesh)
{
        int sup_rates_len;


        /* TODO: move these to a config file */
        ampe_conf.retry_timeout_ms = 1000;
        ampe_conf.holding_timeout_ms = 1000;
        ampe_conf.confirm_timeout_ms = 1000;
        ampe_conf.max_retries = 10;
        ampe_conf.mesh = mesh;

        RAND_bytes(mgtk_tx, 16);
        sae_hexdump(AMPE_DEBUG_KEYS, "mgtk: ", mgtk_tx, sizeof(mgtk_tx));

        /* We can do this because valid supported rates non null and the array is null terminated */
        sup_rates_len = strnlen((char *) mesh->conf->rates, sizeof(mesh->conf->rates));
        if (sup_rates_len <= 8) {
            /*  rates fit into a the supported rates IE */
            sta_fixed_ies_len = 2 + sup_rates_len;
            sta_fixed_ies = malloc(sta_fixed_ies_len);
            *sta_fixed_ies = IEEE80211_EID_SUPPORTED_RATES;
            *(sta_fixed_ies+1) = sup_rates_len;
            memcpy(sta_fixed_ies+2, mesh->conf->rates, sup_rates_len);
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

        sae_hexdump(MESHD_DEBUG , "Fixed Information Elements in this STA", sta_fixed_ies, sta_fixed_ies_len);
        return 0;
}
