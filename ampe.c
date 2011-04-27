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

static unsigned char *meshid[32];
static unsigned char meshid_len;
static struct ampe_config config;
static const unsigned char akm_suite_selector[4] = { 0x0, 0xf, 0xac, 0x8 };     /*  SAE  */
static const unsigned char pw_suite_selector[4] = { 0x0, 0xf, 0xac, 0x4 };     /*  CCMP  */

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
    int offset;
    switch(frame->action.action_code) {
        case PLINK_OPEN:
            offset = 2;
        case PLINK_CONFIRM:
            offset = 4;
        case PLINK_CLOSE:
            offset = 0;
    }
    if (ie_len)
        *ie_len = len - 24 - sizeof(frame->action) - offset;
    return (frame->action.u.var8 + offset);
}

static void plink_timer(timerid id, void *data)
{
	__le16 llid, plid, reason;
    struct candidate *cand;

	cand = (struct candidate *)data;

    sae_debug(AMPE_DEBUG_FSM, "Mesh plink timer for " MACSTR
            " fired on state %s\n", MAC2STR(cand->peer_mac),
		    mplstates[cand->link_state]);
	reason = 0;
	llid = cand->my_lid;
	plid = cand->peer_lid;

	switch (cand->link_state) {
	case PLINK_OPN_RCVD:
	case PLINK_OPN_SNT:
		/* retry timer */
        sae_debug(AMPE_DEBUG_FSM, "Mesh plink:retries %d of %d\n", cand->retries, config.max_retries);
		if (cand->retries < config.max_retries) {
			unsigned int rand;
            sae_debug(AMPE_DEBUG_FSM, "Mesh plink for " MACSTR
                    " (retry, timeout): %d %d\n", MAC2STR(cand->peer_mac),
                    cand->retries, cand->timeout);
			RAND_bytes((unsigned char *) &rand, sizeof(rand));
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
                    SRV_MSEC(config.holding_timeout_ms), plink_timer,
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

static void protect_frame(struct candidate *cand, struct ieee80211_mgmt_frame *mgmt, int len)
{
    unsigned char output[32];
    unsigned char counter[AES_BLOCK_SIZE];
    unsigned char *ies;
    unsigned short ies_len;
    struct info_elems elems;

    assert(len && cand && mgmt);

    /*  Find encrypted mesh peering ie */
	ies = start_of_ies(mgmt, len, &ies_len);
	parse_ies(ies, ies_len, &elems);
	if (!elems.mesh_peering) {
		sae_debug(AMPE_DEBUG_FSM, "protect frame: missing mesh peering ie\n");
		return;
	}

    assert(sizeof(output) > elems.mesh_peering_len);

    siv_init(&cand->sivctx, cand->aek, SIV_256);
    siv_encrypt(&cand->sivctx, elems.mesh_peering, output,
            elems.mesh_peering_len,
            counter, 3,
            cand->my_mac, ETH_ALEN,
            cand->peer_mac, ETH_ALEN,
            &mgmt->action, len - 24);

    sae_hexdump(AMPE_DEBUG_KEYS, "SIV- Put AAD[3]: ", (unsigned char *) &mgmt->action,
            len - 24);

    /*  TODO: Add MIC and AMPE IEs */
}

static void check_frame_protection(struct candidate *cand, struct ieee80211_mgmt_frame *mgmt, int len)
{
    unsigned char output[32];
    unsigned char counter[AES_BLOCK_SIZE];
    unsigned char *ies;
    unsigned short ies_len;
    struct info_elems elems;

    assert(len && cand && mgmt);

	ies = start_of_ies(mgmt, len, &ies_len);
	parse_ies(ies, ies_len, &elems);
	if (!elems.ampe) {
		sae_debug(AMPE_DEBUG_KEYS, "Verify frame: missing ampe ie\n");
		return;
	}

	if (!elems.mic) {
		sae_debug(AMPE_DEBUG_KEYS, "Verify frame: missing mic ie\n");
		return;
	}

    siv_init(&cand->sivctx, cand->aek, SIV_256);
    siv_encrypt(&cand->sivctx, elems.mesh_peering, output,
            elems.mesh_peering_len,
            counter, 3,
            cand->my_mac, ETH_ALEN,
            cand->peer_mac, ETH_ALEN,
            &mgmt->action, len - 24 - elems.ampe_len - elems.mic_len);

    sae_hexdump(AMPE_DEBUG_KEYS, "SIV- Got AAD[3]: ", (unsigned char *) &mgmt->action,
            len - 24 - elems.ampe_len - elems.mic_len);
}

static int plink_frame_tx(struct candidate *cand, enum
        plink_action_code action, unsigned short reason)
{
        unsigned char *buf;
        struct ieee80211_mgmt_frame *mgmt;
        unsigned char *ie_len;
        int len;
        unsigned char *ies;

        assert(cand);

        /* XXX: calculate the right size */
        len = 1000;
        buf = calloc(1, len);
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

	    ies = start_of_ies(mgmt, len, NULL);

        /* IE: Mesh ID element */
        *ies++ = IEEE80211_EID_MESH_ID;
        *ies++ = meshid_len;
        memcpy((char *) ies, meshid, meshid_len);
        ies += meshid_len;

        /* IE: mesh peering (llid, plid, reason and pmk) */
        *ies++ = IEEE80211_EID_MESH_PEERING;
        ie_len = ies++;
        memcpy(ies, &cand->my_lid, 2);
        ies += 2;
        *ie_len = 2;
        if (cand->peer_lid) {
            memcpy(ies, &cand->peer_lid, 2);
            ies += 2;
            *ie_len += 2;
        }
        if (reason) {
            memcpy(ies, &cand->reason, 2);
            ies += 2;
            *ie_len += 2;
        }

        memcpy(ies, cand->pmkid, sizeof(cand->pmkid));
        ies += sizeof(cand->pmkid);
        *ie_len += sizeof(cand->pmkid);

        /* IE: mesh config */
        *ies++ = IEEE80211_EID_MESH_CONFIG;
        *ies++ = 8;
        /*  TODO: IIRC all the defaults are 0. Double check */
        memset(ies, 0, 8);
        ies += 8;

        /* Add AMPE IE */
        *ies++ = IEEE80211_EID_AMPE;
        *ies++ = 68;
        memcpy(ies, pw_suite_selector, 4);
        ies += 4;
        memcpy(ies, cand->my_nonce, 32);
        ies += 32;
        memcpy(ies, cand->peer_nonce, 32);
        ies += 32;
        /*  TODO: Add key replay and GTK fields */

        /* TODO: The kernek will add the MIC IE, but we have to find
         * a way to tell it to do it *before* AMPE.*/

        len = ies - buf;

        protect_frame(cand, (struct ieee80211_mgmt_frame *)buf, len);

        if (meshd_write_mgmt((char *)buf, len, cand->cookie) != len) {
            sae_debug(SAE_DEBUG_ERR, "can't send an authentication "
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
    unsigned short reason = 0;

	switch (cand->link_state) {
	case PLINK_LISTEN:
		switch (event) {
		case CLS_ACPT:
			fsm_restart(cand);
			break;
		case OPN_ACPT:
            cand->timeout = config.retry_timeout_ms;
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
            cand->timeout = config.holding_timeout_ms;
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
            cand->timeout = config.confirm_timeout_ms;
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
            cand->timeout = config.holding_timeout_ms;
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
            // TODO: for now give everyone the same all-zeros mgtk
            memset(cand->mgtk, 0, sizeof(cand->mgtk));
            estab_peer_link(cand->peer_mac, cand->mtk, sizeof(cand->mtk), cand->mgtk, sizeof(cand->mgtk), cand->cookie);
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
            cand->timeout = config.holding_timeout_ms;
            cand->t2 = srv_add_timeout(srvctx, SRV_MSEC(cand->timeout), plink_timer, cand);
			plink_frame_tx(cand, PLINK_CLOSE, reason);
			break;
		case OPN_ACPT:
			cand->link_state = PLINK_ESTAB;
            // TODO: for now give everyone the same all-zeros mgtk
            memset(cand->mgtk, 0, sizeof(cand->mgtk));
            estab_peer_link(cand->peer_mac, cand->mtk, sizeof(cand->mtk), cand->mgtk, sizeof(cand->mgtk), cand->cookie);
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
            cand->timeout = config.holding_timeout_ms;
            cand->t2 = srv_add_timeout(srvctx, SRV_MSEC(cand->timeout), plink_timer, cand);
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
}

#define PLINK_GET_LLID(p) (p + 0)
#define PLINK_GET_PLID(p) (p + 2)

static void derive_aek(struct candidate *cand)
{
    unsigned char context[16];

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
	le16 llid;
    struct candidate *cand;

    assert(peer_mac && me);

 	if ((cand = find_peer(peer_mac, 0)) == NULL) {
        sae_debug(AMPE_DEBUG_FSM, "Mesh plink: Attempt to peer with "
                " non-authed peer\n");
            return -EPERM;
	}

    RAND_bytes((unsigned char *) &llid, 2);
    RAND_bytes(cand->my_nonce, sizeof(cand->my_nonce));
    cand->cookie = cookie;
	cand->my_lid = llid;
	cand->peer_lid = 0;
	cand->link_state = PLINK_OPN_SNT;
    cand->timeout = config.retry_timeout_ms;
    cand->t2 = srv_add_timeout(srvctx, SRV_MSEC(cand->timeout), plink_timer, cand);
    derive_aek(cand);

	sae_debug(AMPE_DEBUG_FSM, "Mesh plink: starting establishment "
            "with " MACSTR "\n", MAC2STR(peer_mac));


	return plink_frame_tx(cand, PLINK_OPEN, 0);
	return 0;
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
    unsigned char ftype;
	struct candidate *cand = NULL;
	enum plink_event event;
	int matches_local = 1;
	unsigned char ie_len = 0;
	unsigned short plid = 0, llid = 0, reason;
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
	if (!elems.mesh_peering || !elems.ampe) {  // || !elems.rsn) {
		sae_debug(AMPE_DEBUG_FSM, "Mesh plink: missing necessary peer link ie\n");
		return 0;
	}

	ftype = mgmt->action.action_code;
	ie_len = elems.mesh_peering_len;

	if ((ftype == PLINK_OPEN && ie_len != 18) ||
	    (ftype == PLINK_CONFIRM && ie_len != 20) ||
	    (ftype == PLINK_CLOSE && ie_len != 20 && ie_len != 22)) {
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

    if ((cand = find_peer(mgmt->sa, 0)) == NULL) {
		sae_debug(AMPE_DEBUG_FSM, "Mesh plink: plink open from unauthed peer\n");
        return 0;
    }

    /* The local nonce in the frame is the peer from the POV of this host. */
 	memcpy(cand->peer_nonce, elems.ampe->local_nonce, 32);
    check_frame_protection(cand, mgmt, len);

    cand->cookie = cookie;



	if (cand->link_state == PLINK_BLOCKED) {
		return 0;
	}

	/* Now we will figure out the appropriate event... */
	event = PLINK_UNDEFINED;
//	if (ftype != PLINK_CLOSE && (!mesh_matches_local(&elems, sdata))) {
	if (ftype != PLINK_CLOSE) {
		matches_local = 0;
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
	reason = 0;

    fsm_step(cand, event);

    return 0;
}

int ampe_initialize(unsigned char *mesh_id, unsigned char len, struct ampe_config *aconfig)
{
        if (len > 32) {
            sae_debug(SAE_DEBUG_ERR, "AMPE: Invalid meshid len");
            return -1;
        }
        meshid_len = len;
        memcpy(meshid, mesh_id, len);
        memcpy(&config, aconfig, sizeof(config));
        return 0;
}
