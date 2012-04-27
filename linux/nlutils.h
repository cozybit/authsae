/*
 * Copyright (c) 2010, cozybit Inc.
 * Javier Cardona, javier@cozybit.com
 *
 * Functions from this file have been liberally copied from libnl
 * documentation and wpa_supplicant. wpa_supplicant is licensed under
 * GPL and has the following copyrights:
 *
 *  Copyright (c) 2002-2010, Jouni Malinen <j@w1.fi>
 *  Copyright (c) 2003-2004, Instant802 Networks, Inc.
 *  Copyright (c) 2005-2006, Devicescape Software, Inc.
 *  Copyright (c) 2007, Johannes Berg <johannes@sipsolutions.net>
 *  Copyright (c) 2009-2010, Atheros Communications
 *
 * cozybit Inc. makes no claim that this file can be linked against
 * authsae or any non-GPL licensed software.
 *
 * cozybit Inc. provides no warranties whatsoever on this software.  If you
 * decide to use it, do it at your own risk.
 *
 */

#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <linux/rtnetlink.h>
#include <netpacket/packet.h>
#include <linux/filter.h>
#include <errno.h>
#include <linux/if_ether.h>
#include "nl80211-copy.h"
#include "ieee802_11.h"

/* leave hw/kernel info here for now, maybe move to common.h? */
#include "stdbool.h"

enum ieee80211_band {
	IEEE80211_BAND_2GHZ = NL80211_BAND_2GHZ,
	IEEE80211_BAND_5GHZ = NL80211_BAND_5GHZ,

	/* keep last */
	IEEE80211_NUM_BANDS
};

struct local_ht_caps {
	uint16_t cap;
	bool ht_supported;
	uint8_t ampdu_factor;
	uint8_t ampdu_density;
	struct mcs_info mcs;
};

struct ieee80211_supported_band {
	uint8_t *rates;
	int n_bitrates;
	struct local_ht_caps ht_cap;
};

struct netlink_config_s {
	struct nl_sock *nl_sock;
	struct nl_cache *nl_cache;
	struct nl_sock *nl_sock_event;
	struct nl_cache *nl_cache_event;
	struct nl_cb *nl_cb;
	struct genl_family *nl80211;
	int supress_error;
	int ifindex;
	int freq;
	uint8_t mymacaddr[ETH_ALEN];
	struct ieee80211_supported_band bands[IEEE80211_NUM_BANDS];
	/* current band */
	enum ieee80211_band band;
};

int netlink_init(struct netlink_config_s *nlcfg, void *event_handler);
int send_nlmsg(struct nl_sock *nl_sock, struct nl_msg *msg);
int send_nlmsg_suppress_error(struct nl_sock *nl_sock,
        struct nl_msg *msg, int expect_err);
