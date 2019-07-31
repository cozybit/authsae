#ifndef _SAE_PEERS_H_
#define _SAE_PEERS_H_

#include <openssl/ec.h>
#include <openssl/ossl_typ.h>
#include <openssl/sha.h>
#include <sys/queue.h>

#include "ampe.h"
#include "common.h"
#include "crypto/siv.h"
#include "ieee802_11.h"

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
#define SAE_NOTHING 0
#define SAE_COMMITTED 1
#define SAE_CONFIRMED 2
#define SAE_ACCEPTED 3
  unsigned short state;
  unsigned short got_token;
  unsigned short sync;
  unsigned short sc;
  unsigned short rc;
  unsigned char peer_mac[ETH_ALEN];
  unsigned char my_mac[ETH_ALEN];
  /*  AMPE related fields */
  timerid t2;
  enum plink_state link_state;
  le16 my_lid;
  le16 peer_lid;
  unsigned char my_nonce[32];
  unsigned char peer_nonce[32];
  unsigned short retries;
  unsigned int timeout;
  unsigned char aek[SHA256_DIGEST_LENGTH];
  unsigned char mtk[KEY_LEN_AES_CCMP];
  unsigned char mgtk[KEY_LEN_AES_CCMP];
  unsigned int mgtk_expiration;

  unsigned char igtk[KEY_LEN_AES_CMAC];
  u16 igtk_keyid;
  bool has_igtk;

  unsigned char sup_rates[MAX_SUPP_RATES];
  unsigned short sup_rates_len;
  siv_ctx sivctx;
  void *cookie;
  struct ampe_config *conf;
  enum channel_width ch_width;
  unsigned short association_id;

  timerid rekey_ping_timer;
  unsigned int rekey_ping_count;
  unsigned int rekey_reauth_count;
  unsigned int rekey_ok;
  unsigned int rekey_ok_ping_rx;

  struct ht_cap_ie *ht_cap;
  struct ht_op_ie *ht_info;

  struct vht_cap_ie *vht_cap;
  struct vht_op_ie *vht_info;

  bool in_kernel;
};

struct candidate *find_peer(unsigned char *mac, int accept);
void delete_peer(struct candidate **peer);
void dump_peer_list();

#endif /* _SAE_PEERS_H_ */
