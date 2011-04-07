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

/**
 * fsm_restart - restart a mesh peer link finite state machine
 *
 * @cand: mesh peer link to restart
 *
 * */
static inline void fsm_restart(struct ampe_state *cand)
{
    cand->state = PLINK_LISTEN;
    cand->llid = cand->plid = cand->reason = 0;
    cand->retries = 0;
}




TAILQ_HEAD(nincompoop, ampe_state) candidates;
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

static struct ampe_state* create_candidate (unsigned char *her_mac, unsigned char *my_mac, void *cookie)
{
    struct ampe_state *cand;

    if ((cand = (struct ampe_state*) malloc(sizeof(struct ampe_state))) == NULL) {
        sae_debug(0x20, "can't malloc space for candidate!\n");
        return NULL;
    }
    memset(cand, 0, sizeof(cand));
    memcpy(cand->local_mac, my_mac, ETH_ALEN);
    memcpy(cand->mac, her_mac, ETH_ALEN);
    cand->state = PLINK_LISTEN;

    return cand;
}

static int plink_free_count() {
    sae_debug(AMPE_DEBUG_CANDIDATES, "TODO: return available peer link slots");
    return 99;
}

static void fsm_step(struct ampe_state *cand, enum plink_event event)
{
    unsigned short reason = 0, plid = 0, llid = 0;

	switch (cand->state) {
	case PLINK_LISTEN:
		switch (event) {
		case CLS_ACPT:
			fsm_restart(cand);
			break;
		case OPN_ACPT:
			cand->state = PLINK_OPN_RCVD;
			//cand->plid = plid;
			//get_random_bytes(&llid, 2);
			//cand->llid = llid;
			//mesh_plink_timer_set(cand, dot11MeshRetryTimeout(sdata));
			//mesh_plink_frame_tx(sdata, PLINK_OPEN, cand->mac, llid,
			//		    0, 0);
			//mesh_plink_frame_tx(sdata, PLINK_CONFIRM, cand->mac,
		                            //llid, plid, 0);
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
			cand->state = PLINK_HOLDING;
			//if (!mod_plink_timer(cand,
			//		     dot11MeshHoldingTimeout(sdata)))
			//	cand->ignore_plink_timer = true;

			llid = cand->llid;
			//mesh_plink_frame_tx(sdata, PLINK_CLOSE, cand->mac, llid,
			//		    plid, reason);
			break;
		case OPN_ACPT:
			/* retry timer is left untouched */
			cand->state = PLINK_OPN_RCVD;
			cand->plid = plid;
			llid = cand->llid;
			//mesh_plink_frame_tx(sdata, PLINK_CONFIRM, cand->mac, llid,
			//		    plid, 0);
			break;
		case CNF_ACPT:
			cand->state = PLINK_CNF_RCVD;
			//if (!mod_plink_timer(cand,
			//		     dot11MeshConfirmTimeout(sdata)))
			//	cand->ignore_plink_timer = true;

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
			cand->state = PLINK_HOLDING;
			//if (!mod_plink_timer(cand,
			//		     dot11MeshHoldingTimeout(sdata)))
			//	cand->ignore_plink_timer = true;

			llid = cand->llid;
			//mesh_plink_frame_tx(sdata, PLINK_CLOSE, cand->mac, llid,
			//		    plid, reason);
			break;
		case OPN_ACPT:
			llid = cand->llid;
			//mesh_plink_frame_tx(sdata, PLINK_CONFIRM, cand->mac, llid,
			//		    plid, 0);
			break;
		case CNF_ACPT:
			//del_timer(&cand->plink_timer);
			cand->state = PLINK_ESTAB;
			//mesh_plink_inc_estab_count(sdata);
			//ieee80211_bss_info_change_notify(sdata, BSS_CHANGED_BEACON);
            sae_debug(AMPE_DEBUG_CANDIDATES, "Mesh plink with %pM "
                "ESTABLISHED\n", cand->mac);
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
			cand->state = PLINK_HOLDING;
			//if (!mod_plink_timer(cand,
			//		     dot11MeshHoldingTimeout(sdata)))
			//	cand->ignore_plink_timer = true;

			llid = cand->llid;
			//mesh_plink_frame_tx(sdata, PLINK_CLOSE, cand->mac, llid,
			//		    plid, reason);
			break;
		case OPN_ACPT:
			//del_timer(&cand->plink_timer);
			cand->state = PLINK_ESTAB;
			//mesh_plink_inc_estab_count(sdata);
			//ieee80211_bss_info_change_notify(sdata, BSS_CHANGED_BEACON);
			sae_debug(AMPE_DEBUG_CANDIDATES, "Mesh plink with %pM ESTABLISHED\n",
				cand->mac);
			//mesh_plink_frame_tx(sdata, PLINK_CONFIRM, cand->mac, llid,
			//		    plid, 0);
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
			//deactivated = __mesh_plink_deactivate(cand);
			cand->state = PLINK_HOLDING;
			llid = cand->llid;
			//mod_plink_timer(cand, dot11MeshHoldingTimeout(sdata));
			//if (deactivated)
		    //	ieee80211_bss_info_change_notify(sdata, BSS_CHANGED_BEACON);
			//mesh_plink_frame_tx(sdata, PLINK_CLOSE, cand->mac, llid,
			//		    plid, reason);
			break;
		case OPN_ACPT:
			llid = cand->llid;
			//mesh_plink_frame_tx(sdata, PLINK_CONFIRM, cand->mac, llid,
			//		    plid, 0);
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
			llid = cand->llid;
			reason = cand->reason;
			//mesh_plink_frame_tx(sdata, PLINK_CLOSE, cand->mac,
			//		    llid, plid, reason);
			break;
		default:
            break;
		}
		break;
	default:
        sae_debug(AMPE_DEBUG_CANDIDATES, "Unsupported event transition %d", event);
		break;
	}
}


/* return status: 0 unless something really bad happened
 */
int process_ampe_frame(struct ieee80211_mgmt_frame *frame, int len, void *cookie)
{
    unsigned char ftype;
	struct ampe_state *cand = NULL;
	enum plink_event event;
	int matches_local = 1;
	unsigned char ie_len = 0;
	unsigned short plid = 0, llid = 0, reason;
	static const char *mplstates[] = {
		[PLINK_LISTEN] = "LISTEN",
		[PLINK_OPN_SNT] = "OPN-SNT",
		[PLINK_OPN_RCVD] = "OPN-RCVD",
		[PLINK_CNF_RCVD] = "CNF_RCVD",
		[PLINK_ESTAB] = "ESTAB",
		[PLINK_HOLDING] = "HOLDING",
		[PLINK_BLOCKED] = "BLOCKED"
	};

	/* need action_code, aux */
	//if (len < IEEE80211_MIN_ACTION_SIZE + 3)
	//	return 0;

	//if (is_multicast_ether_addr(mgmt->da)) {
	//	sae_debug(AMPE_DEBUG_CANDIDATES, "Mesh plink: ignore frame to multicast address");
	//	return 0;
	//}

	//baseaddr = mgmt->u.action.u.plink_action.variable;
	//baselen = (u8 *) mgmt->u.action.u.plink_action.variable - (u8 *) mgmt;
	//if (mgmt->u.action.u.plink_action.action_code == PLINK_CONFIRM) {
	//	baseaddr += 4;
	//	baselen += 4;
	//}
/* 	ieee802_11_parse_elems(baseaddr, len - baselen, &elems);
 * 	if (!elems.peer_link) {
 * 		sae_debug(AMPE_DEBUG_CANDIDATES, "Mesh plink: missing necessary peer link ie\n");
 * 		return 0;
 * 	}
 * 	if (elems.rsn_len &&
 * 			sdata->u.mesh.security == IEEE80211_MESH_SEC_NONE) {
 * 		sae_debug(AMPE_DEBUG_CANDIDATES, "Mesh plink: can't establish link with secure peer\n");
 * 		return 0;
 * 	}
 */

	ftype = frame->action.action_code;
//	ie_len = elems.peer_link_len;
	if ((ftype == PLINK_OPEN && ie_len != 6) ||
	    (ftype == PLINK_CONFIRM && ie_len != 8) ||
	    (ftype == PLINK_CLOSE && ie_len != 8 && ie_len != 10)) {
		sae_debug(AMPE_DEBUG_CANDIDATES, "Mesh plink: incorrect plink ie length %d %d\n",
		    ftype, ie_len);
		return 0;
	}

/* 	if (ftype != PLINK_CLOSE && (!elems.mesh_id || !elems.mesh_config)) {
 * 		sae_debug(AMPE_DEBUG_CANDIDATES, "Mesh plink: missing necessary ie\n");
 * 		return 0;
 * 	}
 */
	/* Note the lines below are correct, the llid in the frame is the plid
	 * from the point of view of this host.
	 */
/* 	memcpy(&plid, PLINK_GET_LLID(elems.peer_link), 2);
 * 	if (ftype == PLINK_CONFIRM || (ftype == PLINK_CLOSE && ie_len == 10))
 * 		memcpy(&llid, PLINK_GET_PLID(elems.peer_link), 2);
 */


	//cand = find_by_address(frame->sa);
	if (!cand && ftype != PLINK_OPEN) {
		sae_debug(AMPE_DEBUG_CANDIDATES, "Mesh plink: cls or cnf from unknown peer\n");
		return 0;
	}

/* 	if (ask_sae_about_this_candidate) {
 * 		sae_debug(AMPE_DEBUG_CANDIDATES, "Mesh plink: Action frame from non-authed peer\n");
 * 		return;
 * 	}
 */

	if (cand && cand->state == PLINK_BLOCKED) {
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

	if (!cand && !matches_local) {
		reason = htole16(MESH_CAPABILITY_POLICY_VIOLATION);
		llid = 0;
//		mesh_plink_frame_tx(sdata, PLINK_CLOSE, mgmt->sa, llid,
//				    plid, reason);
		return 0;
	} else if (!cand) {
		/* ftype == PLINK_OPEN */

		if (!plink_free_count()) {
			sae_debug(AMPE_DEBUG_CANDIDATES, "Mesh plink error: no more free plinks\n");
			return 0;
		}


//		rates = ieee80211_sta_get_rates(local, &elems, rx_status->band);
		cand = create_candidate(frame->sa, NULL, NULL);
		if (!cand) {
			sae_debug(AMPE_DEBUG_CANDIDATES, "Mesh plink error: plink table full\n");
			return 0;
		}
		event = OPN_ACPT;
	} else if (matches_local) {
		switch (ftype) {
		case PLINK_OPEN:
			if (!plink_free_count() ||
			    (cand->plid && cand->plid != plid))
				event = OPN_IGNR;
			else
				event = OPN_ACPT;
			break;
		case PLINK_CONFIRM:
			if (!plink_free_count() ||
			    (cand->llid != llid || cand->plid != plid))
				event = CNF_IGNR;
			else
				event = CNF_ACPT;
			break;
		case PLINK_CLOSE:
			if (cand->state == PLINK_ESTAB)
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
			else if (cand->plid != plid)
				event = CLS_IGNR;
			else if (ie_len == 7 && cand->llid != llid)
				event = CLS_IGNR;
			else
				event = CLS_ACPT;
			break;
		default:
			sae_debug(AMPE_DEBUG_CANDIDATES, "Mesh plink: unknown frame subtype\n");
			return 0;
		}
	}

	sae_debug(AMPE_DEBUG_CANDIDATES, "Mesh plink (peer, state, llid, plid, event): %pM %s %d %d %d\n",
		frame->sa, mplstates[cand->state],
		le16toh(cand->llid), le16toh(cand->plid),
		event);
	reason = 0;

    fsm_step(cand, event);

    return 0;
}
