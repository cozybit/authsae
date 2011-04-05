#ifndef __AMPE_H
#define __AMPE_H

enum mpm_states {
    PLINK_LISTEN,
    PLINK_OPN_SNT,
    PLINK_OPN_RCVD,
    PLINK_CNF_RCVD,
    PLINK_ESTAB,
    PLINK_HOLDING,
    PLINK_BLOCKED
};

struct ampe_candidate {
    TAILQ_ENTRY(ampe_candidate) entry;
    unsigned char pmk[SHA256_DIGEST_LENGTH];
    unsigned char kck[SHA256_DIGEST_LENGTH];
    timerid t0;
    timerid t1;
    enum mpm_states state;
    unsigned char mac[ETH_ALEN];
    unsigned char local_mac[ETH_ALEN];
    void *cookie;
};

int process_ampe_frame(struct ieee80211_mgmt_frame *frame, int len, void *cookie);
#endif
