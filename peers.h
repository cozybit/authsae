#ifndef __PEERS_H
#define __PEERS_H

typedef struct group_def_ {
    unsigned short group_num;
    EC_GROUP *group;
    BIGNUM *order;
    BIGNUM *prime;
    char password[80];
    struct group_def_ *next;
} GD;

struct candidate {
    TAILQ_ENTRY(candidate) entry;
    GD *grp_def;
    EC_POINT *pwe;
    unsigned char pmkid[16];
    unsigned char pmk[SHA256_DIGEST_LENGTH];
    unsigned char kck[SHA256_DIGEST_LENGTH];
    BIGNUM *private_val;
    BIGNUM *peer_scalar;
    BIGNUM *my_scalar;
    EC_POINT *peer_element;
    EC_POINT *my_element;
    unsigned long beacons;
    unsigned int failed_auth;
    timerid t0;
    timerid t1;
#define SAE_NOTHING             0
#define SAE_COMMITTED           1
#define SAE_CONFIRMED           2
#define SAE_ACCEPTED            3
    unsigned short state;
    unsigned short got_token;
    unsigned short sync;
    unsigned short sc;
    unsigned short rc;
    unsigned char peer_mac[ETH_ALEN];
    unsigned char my_mac[ETH_ALEN];
    /*  AMPE related fields */
    timerid t2;
    timerid t3;
    enum plink_state link_state;
    le16 my_lid;
    le16 peer_lid;
    unsigned char my_nonce[32];
    unsigned char peer_nonce[32];
    unsigned short reason;
    unsigned short retries;
    unsigned int timeout;
    unsigned char aek[SHA256_DIGEST_LENGTH];
    unsigned char mtk[16];
    unsigned char mgtk[16];
    unsigned int mgtk_expiration;
    unsigned char igtk[16];
    u16 igtk_keyid;
    unsigned char sup_rates[MAX_SUPP_RATES];
    unsigned short sup_rates_len;
    siv_ctx sivctx;
    void *cookie;
    struct ampe_config *conf;
    unsigned int ch_type; /* nl80211_channel_type */
    int candidate_id;
};

struct candidate *find_peer(unsigned char *mac, int accept);
void delete_peer(struct candidate **peer);

TAILQ_HEAD(fubar, candidate) blacklist;
TAILQ_HEAD(blah, candidate) peers;

#define for_each_peer(peer) \
	TAILQ_FOREACH(peer, &peers, entry)

#endif
