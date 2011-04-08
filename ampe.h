#ifndef __AMPE_H
#define __AMPE_H

enum plink_state {
    PLINK_LISTEN,
    PLINK_OPN_SNT,
    PLINK_OPN_RCVD,
    PLINK_CNF_RCVD,
    PLINK_ESTAB,
    PLINK_HOLDING,
    PLINK_BLOCKED
};

struct ampe_state {
    TAILQ_ENTRY(ampe_state) entry;
#define SHA256_DIGEST_LENGTH	32
    unsigned char pmk[SHA256_DIGEST_LENGTH];
    unsigned char kck[SHA256_DIGEST_LENGTH];
    timerid t0;
    timerid t1;
    enum plink_state state;
    unsigned char mac[ETH_ALEN];
    unsigned char local_mac[ETH_ALEN];
    unsigned short llid;
    unsigned short plid;
    unsigned short reason;
    unsigned short retries;
    void *cookie;
};

int process_ampe_frame(struct ieee80211_mgmt_frame *frame, int len, unsigned char *me, void *cookie);
#endif
