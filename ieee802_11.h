/*
 * Copyright (c) Dan Harkins, 2008, 2009, 2010
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
 *	  or use of this software must display the following acknowledgement:
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

#ifndef _FRAME_H_
#define _FRAME_H_

#include <stdint.h>
#if __BYTE_ORDER == __LITTLE_ENDIAN
/*
 * IEEE does things bassackwards, networking in non-network order.
 */
#define ieee_order(x)   (x)                     /* if LE, do nothing */
#else

static inline unsigned short
ieee_order (unsigned short x)                   /* if BE, byte-swap */
{
    return ((x & 0xff) << 8) | (x >> 8);
}

#endif  /* __LITTLE_ENDIAN */

/*
 * some useful defines...
 */

#ifndef MAC2STR
#define MAC2STR(a) (a)[0]&0xff, (a)[1]&0xff, (a)[2]&0xff, (a)[3]&0xff, (a)[4]&0xff, (a)[5]&0xff
#define MACSTR "%02x:%02x:%02x:%02x:%02x:%02x"
#endif

#define IEEE802_11_FC_GET_TYPE(fc)  (((fc) & 0x000c) >> 2)
#define IEEE802_11_FC_GET_STYPE(fc) (((fc) & 0x00f0) >> 4)

#define WLAN_STATUS_SUCCESSFUL                  0
#define WLAN_STATUS_UNSPECIFIED_FAILURE         1
#define WLAN_STATUS_AUTHENTICATION_TIMEOUT      16
#define WLAN_STATUS_REQUEST_DECLINED            37
#define WLAN_STATUS_ANTI_CLOGGING_TOKEN_NEEDED  76
#define WLAN_STATUS_NOT_SUPPORTED_GROUP         77

#define IEEE802_11_IE_SSID                      0
#define IEEE802_11_HDR_LEN                      24

#define ETH_ALEN                                6

/* for ht_param */
#define IEEE80211_HT_PARAM_CHA_SEC_OFFSET               0x03
#define         IEEE80211_HT_PARAM_CHA_SEC_NONE         0x00
#define         IEEE80211_HT_PARAM_CHA_SEC_ABOVE        0x01
#define         IEEE80211_HT_PARAM_CHA_SEC_BELOW        0x03
#define IEEE80211_HT_PARAM_CHAN_WIDTH_ANY               0x04

/* for operation_mode */
#define IEEE80211_HT_OP_MODE_PROTECTION                 0x0003
#define         IEEE80211_HT_OP_MODE_PROTECTION_NONE            0
#define         IEEE80211_HT_OP_MODE_PROTECTION_NONMEMBER       1
#define         IEEE80211_HT_OP_MODE_PROTECTION_20MHZ           2
#define         IEEE80211_HT_OP_MODE_PROTECTION_NONHT_MIXED     3
#define IEEE80211_HT_OP_MODE_NON_GF_STA_PRSNT           0x0004
#define IEEE80211_HT_OP_MODE_NON_HT_STA_PRSNT           0x0010

/* 802.11n HT capabilities masks (for cap_info) */
#define IEEE80211_HT_CAP_LDPC_CODING            0x0001
#define IEEE80211_HT_CAP_SUP_WIDTH_20_40        0x0002
#define IEEE80211_HT_CAP_SM_PS                  0x000C
#define         IEEE80211_HT_CAP_SM_PS_SHIFT    2
#define IEEE80211_HT_CAP_GRN_FLD                0x0010
#define IEEE80211_HT_CAP_SGI_20                 0x0020
#define IEEE80211_HT_CAP_SGI_40                 0x0040
#define IEEE80211_HT_CAP_TX_STBC                0x0080
#define IEEE80211_HT_CAP_RX_STBC                0x0300
#define         IEEE80211_HT_CAP_RX_STBC_SHIFT  8
#define IEEE80211_HT_CAP_DELAY_BA               0x0400
#define IEEE80211_HT_CAP_MAX_AMSDU              0x0800
#define IEEE80211_HT_CAP_DSSSCCK40              0x1000
#define IEEE80211_HT_CAP_RESERVED               0x2000
#define IEEE80211_HT_CAP_40MHZ_INTOLERANT       0x4000
#define IEEE80211_HT_CAP_LSIG_TXOP_PROT         0x8000

/*
 * all we're interested in is mgmt frames of subtype beacon and auth,
 * so instead of depending on platform-specific data structures just
 * declare our own minimal one.
 */
struct ieee80211_mgmt_frame {
    unsigned short frame_control;
#define IEEE802_11_FC_TYPE_MGMT 0
#define IEEE802_11_FC_STYPE_BEACON 8
#define IEEE802_11_FC_STYPE_AUTH 11
#define IEEE802_11_FC_STYPE_ACTION 13
    unsigned short duration;
    unsigned char da[ETH_ALEN];
    unsigned char sa[ETH_ALEN];
    unsigned char bssid[ETH_ALEN];
    unsigned short seq;
    union {
        struct {
#define SAE_AUTH_ALG                    3
            unsigned short alg;
#define SAE_AUTH_COMMIT                 1
#define SAE_AUTH_CONFIRM                2
            unsigned short auth_seq;
            unsigned short status;
            union {
                unsigned char var8[0];
                unsigned short var16[0];
            }u;
        } __attribute__ ((packed)) authenticate;
        struct {
            unsigned char timestamp[8];
            unsigned short interval;
            unsigned short capabilities;
            union {
                unsigned char var8[0];
                unsigned short var16[0];
            }u;
        } __attribute__ ((packed)) beacon;
        struct {
            unsigned char category;
            unsigned char action_code;
            /* PLINK_OPEN has these fields before IES:*/
            /*  Capability (2 bytes) */
            /* PLINK_CONFIRM has these fields before IES:*/
            /*  Capability (2 bytes) */
            /*  AID (2 bytes) */
            /* PLINK_CLOSE has no additional fixed length fields */
            union {
                unsigned char var8[0];
                unsigned short var16[0];
            }u;
        } __attribute__ ((packed)) action;
    };
} __attribute__ ((packed));

enum plink_action_code {
        PLINK_OPEN = 1,
        PLINK_CONFIRM,
        PLINK_CLOSE
};

enum ieee_ie_ids {
    IEEE80211_EID_SUPPORTED_RATES = 1,
    IEEE80211_EID_HT_CAPABILITY = 45,
    IEEE80211_EID_RSN = 48,
    IEEE80211_EID_EXTENDED_SUP_RATES = 50,
    IEEE80211_EID_HT_OPERATION = 61,
    IEEE80211_EID_MESH_CONFIG = 113,
    IEEE80211_EID_MESH_ID = 114,
    IEEE80211_EID_MESH_PEERING = 117,
    IEEE80211_EID_AMPE = 139,
    IEEE80211_EID_MIC = 140,
};

enum ieee_categories {
    IEEE80211_CATEGORY_MESH_ACTION = 13,
    IEEE80211_CATEGORY_SELF_PROTECTED = 15,
};

struct ampe_ie {
    unsigned char selected_pairwise_suite[4];
    unsigned char local_nonce[32];
    unsigned char peer_nonce[32];
    unsigned char mgtk[16];
    unsigned char key_rsc[8];
    unsigned char key_expiration[4];
} __attribute__ ((packed));

struct mcs_info {
    uint8_t rx_mask[10];
    uint16_t rx_highest;
    uint8_t tx_params;
    uint8_t reserved[3];
} __attribute__((packed));

struct ht_cap_ie {
    uint16_t cap_info; /* le */
    uint8_t ampdu_params_info;

    /* 16 bytes MCS information */
    struct mcs_info mcs;

    uint16_t extended_ht_cap_info;	/* le */
    uint32_t tx_BF_cap_info;	/* le */
    uint8_t antenna_selection_info;
} __attribute__ ((packed));

struct ht_op_ie {
    uint8_t primary_chan;
    uint8_t ht_param;
    uint16_t operation_mode; /* le */
    uint16_t stbc_param;	/* le */
    uint8_t basic_set[16];
} __attribute__ ((packed));

struct info_elems {
    unsigned char *sup_rates;
    unsigned char sup_rates_len;

    unsigned char *ext_rates;
    unsigned char ext_rates_len;

    unsigned char *rsn;
    unsigned char rsn_len;

    unsigned char *mesh_peering;
    unsigned char mesh_peering_len;

    unsigned char *mesh_id;
    unsigned char mesh_id_len;

    unsigned char *mesh_config;
    unsigned char mesh_config_len;

    unsigned char *ht_cap;
    unsigned char ht_cap_len;

    unsigned char *ht_info;
    unsigned char ht_info_len;

    struct ampe_ie *ampe;
    unsigned char ampe_len;

    unsigned char *mic;
    unsigned char mic_len;
};

void parse_ies(unsigned char *start, int len, struct info_elems *elems);
#endif  /* _FRAME_H_ */
