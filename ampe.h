#ifndef __AMPE_H
#define __AMPE_H

#include <stdbool.h>
#include "common.h"
#include "ieee802_11.h"
/* meh */
#include "linux/nl80211-copy.h"

unsigned char mgtk_tx[16];
unsigned char *sta_fixed_ies;
unsigned char sta_fixed_ies_len;

enum plink_state {
    PLINK_LISTEN,
    PLINK_OPN_SNT,
    PLINK_OPN_RCVD,
    PLINK_CNF_RCVD,
    PLINK_ESTAB,
    PLINK_HOLDING,
    PLINK_BLOCKED
};

enum ieee80211_band {
	IEEE80211_BAND_2GHZ,
	IEEE80211_BAND_5GHZ,

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
	uint16_t *rates;
	int n_bitrates;
	struct local_ht_caps ht_cap;
};

/* mesh configuration parameters. Our bss_conf */
struct meshd_config {
    char interface[IFNAMSIZ + 1];
    char meshid[MESHD_MAX_SSID_LEN + 1];
    int meshid_len;
    int passive;
    int beacon;
    int mediaopt;
    int channel;
    int band;
    int debug;
    enum nl80211_channel_type channel_type;     /* HT mode */
    /* ready to be copied into rate IEs. Includes BSSBasicRateSet */
#define MAX_SUPP_RATES 32
    unsigned char rates[MAX_SUPP_RATES];
    uint16_t ht_prot_mode;
    int mcast_rate;
};

/* the single global interface and mesh node info we're handling.
 * BSS configuration stuff would also go here. Shared with AMPE. */
struct mesh_node {
    int freq;
    enum nl80211_channel_type channel_type;     /* HT mode */
    uint8_t mymacaddr[ETH_ALEN];
    struct ieee80211_supported_band bands[IEEE80211_NUM_BANDS];
    /* current band */
    enum ieee80211_band band;
    struct meshd_config *conf;
};

struct ampe_config {
    unsigned int retry_timeout_ms;
    unsigned int holding_timeout_ms;
    unsigned int confirm_timeout_ms;
    unsigned int max_retries;
    struct mesh_node *mesh;
};

/* meshd_set_mesh_conf */
#define MESH_CONF_CHANGED_HT 1 << 0

/*  meshd calls these:  */
int ampe_initialize(struct mesh_node *mesh);
int process_ampe_frame(struct ieee80211_mgmt_frame *frame, int len, unsigned char *me, void *cookie);
int start_peer_link(unsigned char *peer_mac, unsigned char *me, void *cookie);

/*  and implements these:  */
int meshd_set_mesh_conf(struct mesh_node *mesh, uint32_t changed);
void estab_peer_link(unsigned char *peer, unsigned char *mtk,
        int mtk_len, unsigned char *peer_mgtk, int peer_mgtk_len,
        unsigned int mgtk_expiration,
        unsigned char *sup_rates,
        unsigned short sup_rates_len,
        void *cookie);
#endif
