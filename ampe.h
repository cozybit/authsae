#ifndef _SAE_AMPE_H_
#define _SAE_AMPE_H_

#include <net/if.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>

#include "common.h"
#include "ieee802_11.h"

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

/* For Linux these values need to match NL80211_CHAN_XXX equivs */
enum ht_channel_type {
	CHAN_NO_HT,
	CHAN_HT20,
	CHAN_HT40MINUS,
	CHAN_HT40PLUS
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

typedef union {
    struct in_addr v4; /* in network byte order */
    struct in6_addr v6; /* in network byte order */
} ip_address;

/* mesh configuration parameters. Our bss_conf */
struct meshd_config {
    char interface[IFNAMSIZ + 1];
    char meshid[MESHD_MAX_SSID_LEN + 1];
    int meshid_len;
    int passive;
    int mediaopt;
    int channel;
    int band;
    int debug;
    enum ht_channel_type channel_type;     /* HT mode */
    /* ready to be copied into rate IEs. Includes BSSBasicRateSet */
#define MAX_SUPP_RATES 32
    unsigned char rates[MAX_SUPP_RATES];
    uint16_t ht_prot_mode;
    int pmf;
    int mcast_rate;
    int beacon_interval;
    int path_refresh_time;
    int min_discovery_timeout;
    int gate_announcements;
    int hwmp_active_path_timeout;
    int hwmp_net_diameter_traversal_time;
    int hwmp_rootmode;
    int hwmp_rann_interval;
    int hwmp_active_path_to_root_timeout;
    int hwmp_root_interval;

    int rekey_enable;
    char bridge[IFNAMSIZ];
    int rekey_multicast_group_family;
    ip_address rekey_multicast_group_address; /* in network byte order */
    int rekey_ping_port; /* in network byte order */
    int rekey_pong_port; /* in network byte order */
    int rekey_ping_count_max;
    int rekey_ping_timeout; /* in msec */
    int rekey_ping_jitter; /* in msec */
    int rekey_reauth_count_max;
    int rekey_ok_ping_count_max;
};

/* the single global interface and mesh node info we're handling.
 * BSS configuration stuff would also go here. Shared with AMPE. */
struct mesh_node {
    int freq;
    enum ht_channel_type channel_type;     /* HT mode */
    uint8_t mymacaddr[ETH_ALEN];
    struct ieee80211_supported_band bands[IEEE80211_NUM_BANDS];
    /* current band */
    enum ieee80211_band band;
    struct meshd_config *conf;

    /* integrity protection key */
    int igtk_keyid;
    uint8_t igtk_ipn[6];
    uint8_t igtk_tx[16];
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
int set_plink_state(unsigned char *peer, int state, void *cookie);
void estab_peer_link(unsigned char *peer, unsigned char *mtk,
        int mtk_len, unsigned char *peer_mgtk, int peer_mgtk_len,
        unsigned int mgtk_expiration,
        unsigned char *peer_igtk, int peer_igtk_len, int peer_igtk_keyid,
        unsigned char *sup_rates,
        unsigned short sup_rates_len,
        void *cookie);

#endif /* _SAE_AMPE_H_ */
