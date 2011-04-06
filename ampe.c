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

static struct ampe_state*
create_candidate (unsigned char *her_mac, unsigned char *my_mac, void *cookie)
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


void mpm_fsm_step(struct ampe_state *cand, enum plink_event event)
{
    unsigned short reason = 0, plid = 0, llid = 0;

	switch (cand->state) {
	case PLINK_LISTEN:
		switch (event) {
		case CLS_ACPT:
			//mesh_plink_fsm_restart(sta);
			break;
		case OPN_ACPT:
			cand->state = PLINK_OPN_RCVD;
			//cand->plid = plid;
			//get_random_bytes(&llid, 2);
			//cand->llid = llid;
			//mesh_plink_timer_set(sta, dot11MeshRetryTimeout(sdata));
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
			//if (!mod_plink_timer(sta,
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
			//if (!mod_plink_timer(sta,
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
			//if (!mod_plink_timer(sta,
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
			//if (!mod_plink_timer(sta,
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
			//deactivated = __mesh_plink_deactivate(sta);
			cand->state = PLINK_HOLDING;
			llid = cand->llid;
			//mod_plink_timer(sta, dot11MeshHoldingTimeout(sdata));
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
			//mesh_plink_fsm_restart(sta);
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

int process_ampe_frame(struct ieee80211_mgmt_frame *frame, int len, void *cookie)
{
    create_candidate (NULL, NULL, NULL);
    return 0;
}


