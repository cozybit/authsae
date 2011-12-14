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
#include "crypto/siv.h"
#include "peers.h"

#define COUNTER_INFINITY        65535


#define state_to_string(x) (x) == SAE_NOTHING ? "NOTHING" : \
                           (x) == SAE_COMMITTED ? "COMMITTED" : \
                           (x) == SAE_CONFIRMED ? "CONFIRMED" : \
                           (x) == SAE_ACCEPTED ? "ACCEPTED" : \
                           "unknown"

#define seq_to_string(x) (x) == SAE_AUTH_COMMIT ? "COMMIT" : \
                         (x) == SAE_AUTH_CONFIRM ? "CONFIRM" : \
                         "unknown"

#define status_to_string(x) (x) == WLAN_STATUS_ANTI_CLOGGING_TOKEN_NEEDED ? "TOKEN NEEDED" : \
                            (x) == WLAN_STATUS_NOT_SUPPORTED_GROUP ? "REJECTION" : \
                            "unknown"

/*
 * the functions H() and CN()
 */
#define H_Init(ctx,x,l) HMAC_Init((ctx), (x), (l), EVP_sha256())
#define H_Update(ctx,x,l) HMAC_Update((ctx),(x),(l))
#define H_Final(ctx,x) HMAC_Final((ctx), (x), &function_mdlen)

#define CN_Init(ctx,x,l) HMAC_Init((ctx), (x), (l), EVP_sha256())
#define CN_Update(ctx,x,l) HMAC_Update((ctx),(x),(l))
#define CN_Final(ctx,x) HMAC_Final((ctx), (x), &function_mdlen)

extern service_context srvctx;
/*
 * forward declarations
 */
static void reauth(timerid id, void *data);

/*
 * global variables
 */
BN_CTX *bnctx = NULL;
GD *gd;                                 /* group definitions */
BIO *out;
int curr_open, open_threshold, retrans;
unsigned long blacklist_timeout, giveup_threshold, pmk_expiry;
unsigned long token_generator;
#if 0
char mesh_ssid[33]
#endif
char conffile[80], allzero[SHA256_DIGEST_LENGTH];
unsigned int function_mdlen = SHA256_DIGEST_LENGTH;

enum result {
    NO_ERR,
    ERR_NOT_FATAL,
    ERR_FATAL,
    ERR_BLACKLIST
};

static void
dump_buffer (unsigned char *buf, int len)
{
    int i;

    for (i = 0; i < len; i++) {
        if (i && (i%4 == 0)) {
            printf(" ");
        }
        if (i && (i%32 == 0)) {
            printf("\n");
        }
        printf("%02x", buf[i]);
    }
    printf("\n");
}

static void
print_buffer (char *str, unsigned char *buf, int len)
{
    printf("%s:\n", str);
    dump_buffer(buf, len);
    printf("\n");
}

static void
pp_a_bignum (char *str, BIGNUM *bn)
{
    unsigned char *buf;
    int len;

    len = BN_num_bytes(bn);
    if ((buf = malloc(len)) == NULL) {
        return;
    }
    BN_bn2bin(bn, buf);
    print_buffer(str, buf, len);
    free(buf);
}

int
prf (unsigned char *key, int keylen, unsigned char *label, int labellen,
     unsigned char *context, int contextlen,
     unsigned char *result, int resultbitlen)
{
    HMAC_CTX ctx;
    unsigned char i = 0, digest[SHA256_DIGEST_LENGTH];
    int resultlen, len = 0;
    unsigned int mdlen = SHA256_DIGEST_LENGTH;
    unsigned char mask = 0xff;
    unsigned short reslength;

    reslength = ieee_order(resultbitlen);
    resultlen = (resultbitlen + 7)/8;
    do {
        i++;
        HMAC_Init(&ctx, key, keylen, EVP_sha256());
        HMAC_Update(&ctx, &i, sizeof(i));
        HMAC_Update(&ctx, label, labellen);
        HMAC_Update(&ctx, context, contextlen);
        HMAC_Update(&ctx, (unsigned char *)&reslength, sizeof(unsigned short));
        HMAC_Final(&ctx, digest, &mdlen);
        if ((len + mdlen) > resultlen) {
            memcpy(result+len, digest, resultlen - len);
        } else {
            memcpy(result+len, digest, mdlen);
        }
        len += mdlen;
        HMAC_CTX_cleanup(&ctx);
    } while (len < resultlen);
    /*
     * we're expanding to a bit length, if this is not a
     * multiple of 8 bits then mask off the excess.
     */
    if (resultbitlen % 8) {
        mask <<= (8 - (resultbitlen % 8));
        result[resultlen - 1] &= mask;
    }
    return resultlen;
}

static void
remove_from_blacklist (timerid id, void *data)
{
    struct candidate *peer, *delme;

    delme = (struct candidate *)data;
    TAILQ_FOREACH(peer, &blacklist, entry) {
        if (memcmp(delme->peer_mac, peer->peer_mac, ETH_ALEN) == 0) {
            sae_debug(SAE_DEBUG_PROTOCOL_MSG, "removing " MACSTR " from blacklist\n", MAC2STR(peer->peer_mac));
            TAILQ_REMOVE(&blacklist, peer, entry);
            free(delme);
            return;
        }
    }
}

static void
blacklist_peer (struct candidate *peer)
{
    struct candidate *fubar;
    if ((fubar = (struct candidate *)malloc(sizeof(struct candidate))) != NULL) {
        memcpy(fubar->peer_mac, peer->peer_mac, ETH_ALEN);
        TAILQ_INSERT_TAIL(&blacklist, fubar, entry);
        (void)srv_add_timeout(srvctx, SRV_SEC(blacklist_timeout), remove_from_blacklist, fubar);
    }
}

/*
 * delete_peer()
 *      Clean up state, remove peer from database, and free up memory.
 */
void
delete_peer (struct candidate **delme)
{
    struct candidate *peer;

    TAILQ_FOREACH(peer, &peers, entry) {
        if (memcmp(*delme, peer, sizeof(struct candidate)) == 0) {
            sae_debug(SAE_DEBUG_PROTOCOL_MSG, "deleting peer at " MACSTR " in state %s\n",
                      MAC2STR(peer->peer_mac), state_to_string(peer->state));
            if ((peer->state == SAE_COMMITTED) || (peer->state == SAE_CONFIRMED)) {
                curr_open--;
                if (curr_open < 0) {
                    /*
                     * one of those "should not happen" kinds of things
                     */
                    sae_debug(SAE_DEBUG_ERR, "***ERROR*** we have %d currently open sessions\n", curr_open);
                }
            }
            srv_rem_timeout(srvctx, peer->t0);     /* no harm if not set */
            srv_rem_timeout(srvctx, peer->t1);     /*      ditto         */
            TAILQ_REMOVE(&peers, peer, entry);
            /*
             * PWE, the private value, the PMK and KCK are all secret so
             * take some special care when deleting them.
             */
            EC_POINT_clear_free(peer->pwe);
            BN_clear_free(peer->private_val);
            memset(peer->pmk, 0, SHA256_DIGEST_LENGTH);
            memset(peer->kck, 0, SHA256_DIGEST_LENGTH);
            BN_free(peer->peer_scalar);
            EC_POINT_free(peer->peer_element);
            BN_free(peer->my_scalar);
            EC_POINT_free(peer->my_element);
            free(*delme);
            *delme = NULL;
            return;
        }
    }
    sae_debug(SAE_DEBUG_ERR, "failed to delete peer :-( \n");
}

/*
 * a callback-able version of delete peer
 */
static void
destroy_peer (timerid id, void *data)
{
    struct candidate *peer = (struct candidate *)data;

    delete_peer(&peer);
}

static int
on_blacklist (unsigned char *mac)
{
    struct candidate *peer;

    TAILQ_FOREACH(peer, &blacklist, entry) {
        if (memcmp(peer->peer_mac, mac, ETH_ALEN) == 0) {
            return 1;
        }
    }
    return 0;
}

struct candidate *
find_peer (unsigned char *mac, int accept)
{
    struct candidate *peer, *found = NULL;

    TAILQ_FOREACH(peer, &peers, entry) {
        if (memcmp(peer->peer_mac, mac, ETH_ALEN) == 0) {
            /*
             * if "accept" then we're only looking for peers in "accepted" state
             */
            if (accept) {
                if (peer->state == SAE_ACCEPTED) {
                    return peer;
                }
                continue;
            }
            /*
             * otherwise we'll take any peer but, if there are 2, give preference
             * to the one not in "accepted" state
             */
            if (found == NULL) {
                found = peer;
            } else {
                if ((found->state == SAE_ACCEPTED) &&
                    (peer->state != SAE_ACCEPTED)) {
                    found = peer;
                }
            }
        }
    }
    return found;
}

static int
check_dup (struct candidate *peer, int check_me, struct ieee80211_mgmt_frame *frame, int len)
{
    unsigned char *ptr;
    int itemsize, ret;
    BIGNUM *scalar;

    if ((scalar = BN_new()) == NULL) {
        /*
         * this seems kind of serious so return that it is a dupe so we don't
         * do anymore processing of this frame
         */
        return 0;
    }
    ptr = frame->authenticate.u.var8 + sizeof(unsigned short);
    if (peer->got_token) {
        /*
         * we know how big the token is because we generated it in the first place!
         */
        ptr += SHA256_DIGEST_LENGTH;
    }
    itemsize = BN_num_bytes(peer->grp_def->order);
    BN_bin2bn(ptr, itemsize, scalar);
    if (check_me) {
        ret = BN_cmp(peer->my_scalar, scalar);
    } else {
        ret = BN_cmp(peer->peer_scalar, scalar);
    }
    BN_free(scalar);
    return ret;
}

static int
check_confirm (struct candidate *peer, struct ieee80211_mgmt_frame *frame)
{
    unsigned short sent_confirm;

    sent_confirm = *(frame->authenticate.u.var16);
    if ((sent_confirm > peer->rc) && (sent_confirm != COUNTER_INFINITY)) {
        return 1;
    } else {
        return 0;
    }
}

static int
process_confirm (struct candidate *peer, struct ieee80211_mgmt_frame *frame, int len)
{
    unsigned char tmp[128];
    BIGNUM *x, *y;
    EC_POINT *psum;
    HMAC_CTX ctx;
    int offset;

    if (len != (IEEE802_11_HDR_LEN + sizeof(frame->authenticate) + sizeof(unsigned short) + SHA256_DIGEST_LENGTH)) {
        sae_debug(SAE_DEBUG_ERR, "bad size of confirm message (%d)\n", len);
        return ERR_NOT_FATAL;
    }
    if (((x = BN_new()) == NULL) ||
        ((y = BN_new()) == NULL) ||
        ((psum = EC_POINT_new(peer->grp_def->group)) == NULL)) {
        sae_debug(SAE_DEBUG_ERR, "unable to construct confirm!\n");
        return ERR_FATAL;
    }

    CN_Init(&ctx, peer->kck, SHA256_DIGEST_LENGTH);     /* the key */

    peer->rc = ieee_order(*(frame->authenticate.u.var16));
    sae_debug(SAE_DEBUG_PROTOCOL_MSG, "processing confirm (%d)\n", peer->rc);
    /*
     * compute the confirm verifier using the over-the-air format of send_conf
     */
    CN_Update(&ctx, frame->authenticate.u.var8, sizeof(unsigned short));

        /* peer's scalar */
    offset = BN_num_bytes(peer->grp_def->order) - BN_num_bytes(peer->peer_scalar);
    memset(tmp, 0, offset);
    BN_bn2bin(peer->peer_scalar, tmp + offset);
    CN_Update(&ctx, tmp, BN_num_bytes(peer->grp_def->order));

    if (!EC_POINT_get_affine_coordinates_GFp(peer->grp_def->group, peer->peer_element, x, y, bnctx)) {
        sae_debug(SAE_DEBUG_ERR, "unable to get x,y of peer's element\n");
        BN_free(x);
        BN_free(y);
        EC_POINT_free(psum);
        return ERR_NOT_FATAL;
    }
        /* peer's element */
    offset = BN_num_bytes(peer->grp_def->prime) - BN_num_bytes(x);
    memset(tmp, 0, offset);
    BN_bn2bin(x, tmp + offset);
    CN_Update(&ctx, tmp, BN_num_bytes(peer->grp_def->prime));
    offset = BN_num_bytes(peer->grp_def->prime) - BN_num_bytes(y);
    memset(tmp, 0, offset);
    BN_bn2bin(y, tmp + offset);
    CN_Update(&ctx, tmp, BN_num_bytes(peer->grp_def->prime));

        /* my scalar */
    offset = BN_num_bytes(peer->grp_def->order) - BN_num_bytes(peer->my_scalar);
    memset(tmp, 0, offset);
    BN_bn2bin(peer->my_scalar, tmp + offset);
    CN_Update(&ctx, tmp, BN_num_bytes(peer->grp_def->order));

    if (!EC_POINT_get_affine_coordinates_GFp(peer->grp_def->group, peer->my_element, x, y, bnctx)) {
        sae_debug(SAE_DEBUG_ERR, "unable to get x,y of my element\n");
        BN_free(x);
        BN_free(y);
        EC_POINT_free(psum);
        return ERR_NOT_FATAL;
    }
        /* my element */
    offset = BN_num_bytes(peer->grp_def->prime) - BN_num_bytes(x);
    memset(tmp, 0, offset);
    BN_bn2bin(x, tmp + offset);
    CN_Update(&ctx, tmp, BN_num_bytes(peer->grp_def->prime));
    offset = BN_num_bytes(peer->grp_def->prime) - BN_num_bytes(y);
    memset(tmp, 0, offset);
    BN_bn2bin(y, tmp + offset);
    CN_Update(&ctx, tmp, BN_num_bytes(peer->grp_def->prime));

    CN_Final(&ctx, tmp);

    if (sae_debug_mask & SAE_DEBUG_CRYPTO_VERB) {
        print_buffer("peer's confirm",
                    frame->authenticate.u.var8,
                    SHA256_DIGEST_LENGTH + sizeof(unsigned short));
    }

    if (memcmp(tmp, (frame->authenticate.u.var8 + sizeof(unsigned short)), SHA256_DIGEST_LENGTH)) {
        sae_debug(SAE_DEBUG_ERR, "confirm did not verify!\n");
        BN_free(x);
        BN_free(y);
        EC_POINT_free(psum);
        return ERR_BLACKLIST;
    }

    BN_free(x);
    BN_free(y);
    EC_POINT_free(psum);
    return NO_ERR;
}

static int
confirm_to_peer (struct candidate *peer)
{
    char buf[2048];
    unsigned char tmp[128];
    struct ieee80211_mgmt_frame *frame;
    size_t len = 0;
    BIGNUM *x, *y;
    HMAC_CTX ctx;
    unsigned short send_conf;
    int offset;

    if (((x = BN_new()) == NULL) ||
        ((y = BN_new()) == NULL)) {
        sae_debug(SAE_DEBUG_ERR, "unable to construct confirm!\n");
        return -1;
    }

    memset(buf, 0, sizeof(buf));
    frame = (struct ieee80211_mgmt_frame *)buf;

    frame->frame_control = ieee_order((IEEE802_11_FC_TYPE_MGMT << 2 | IEEE802_11_FC_STYPE_AUTH << 4));
    memcpy(frame->sa, peer->my_mac, ETH_ALEN);
    memcpy(frame->da, peer->peer_mac, ETH_ALEN);
    memcpy(frame->bssid, peer->peer_mac, ETH_ALEN);

    frame->authenticate.alg = ieee_order(SAE_AUTH_ALG);
    frame->authenticate.auth_seq = ieee_order(SAE_AUTH_CONFIRM);
    len = IEEE802_11_HDR_LEN + sizeof(frame->authenticate);

    if (peer->sc != COUNTER_INFINITY) {
        peer->sc++;
    }
    send_conf = ieee_order(peer->sc);
    memcpy(frame->authenticate.u.var8, (unsigned char *)&send_conf, sizeof(unsigned short));
    len += sizeof(unsigned short);


    CN_Init(&ctx, peer->kck, SHA256_DIGEST_LENGTH);     /* the key */

    /* send_conf is in over-the-air format now */
    CN_Update(&ctx, (unsigned char *)&send_conf, sizeof(unsigned short));

        /* my scalar */
    offset = BN_num_bytes(peer->grp_def->order) - BN_num_bytes(peer->my_scalar);
    memset(tmp, 0, offset);
    BN_bn2bin(peer->my_scalar, tmp + offset);
    CN_Update(&ctx, tmp, BN_num_bytes(peer->grp_def->order));

    if (!EC_POINT_get_affine_coordinates_GFp(peer->grp_def->group, peer->my_element, x, y, bnctx)) {
        sae_debug(SAE_DEBUG_ERR, "unable to get x,y of my element\n");
        BN_free(x);
        BN_free(y);
        return -1;
    }
        /* my element */
    offset = BN_num_bytes(peer->grp_def->prime) - BN_num_bytes(x);
    memset(tmp, 0, offset);
    BN_bn2bin(x, tmp + offset);
    CN_Update(&ctx, tmp, BN_num_bytes(peer->grp_def->prime));
    offset = BN_num_bytes(peer->grp_def->prime) - BN_num_bytes(y);
    memset(tmp, 0, offset);
    BN_bn2bin(y, tmp + offset);
    CN_Update(&ctx, tmp, BN_num_bytes(peer->grp_def->prime));

        /* peer's scalar */
    offset = BN_num_bytes(peer->grp_def->order) - BN_num_bytes(peer->peer_scalar);
    memset(tmp, 0, offset);
    BN_bn2bin(peer->peer_scalar, tmp + offset);
    CN_Update(&ctx, tmp, BN_num_bytes(peer->grp_def->order));

    if (!EC_POINT_get_affine_coordinates_GFp(peer->grp_def->group, peer->peer_element, x, y, bnctx)) {
        sae_debug(SAE_DEBUG_ERR, "unable to get x,y of peer's element\n");
        BN_free(x);
        BN_free(y);
        return -1;
    }
        /* peer's element */
    offset = BN_num_bytes(peer->grp_def->prime) - BN_num_bytes(x);
    memset(tmp, 0, offset);
    BN_bn2bin(x, tmp + offset);
    CN_Update(&ctx, tmp, BN_num_bytes(peer->grp_def->prime));
    offset = BN_num_bytes(peer->grp_def->prime) - BN_num_bytes(y);
    memset(tmp, 0, offset);
    BN_bn2bin(y, tmp + offset);
    CN_Update(&ctx, tmp, BN_num_bytes(peer->grp_def->prime));

    CN_Final(&ctx, (frame->authenticate.u.var8 + sizeof(unsigned short)));

    if (sae_debug_mask & SAE_DEBUG_CRYPTO_VERB) {
        print_buffer("local confirm",
                    frame->authenticate.u.var8,
                    SHA256_DIGEST_LENGTH + sizeof(unsigned short));
    }

    len += SHA256_DIGEST_LENGTH;

    sae_debug(SAE_DEBUG_PROTOCOL_MSG, "in %s, sending %s (sc=%d), len %d\n",
              state_to_string(peer->state),
              seq_to_string(ieee_order(frame->authenticate.auth_seq)),
              peer->sc, len);
    if (meshd_write_mgmt(buf, len, peer->cookie) != len) {
        sae_debug(SAE_DEBUG_ERR, "can't send an authentication frame to " MACSTR "\n",
                MAC2STR(peer->peer_mac));
        return -1;
    }
    BN_free(x);
    BN_free(y);

    return 0;
}

static int
process_commit (struct candidate *peer, struct ieee80211_mgmt_frame *frame, int len)
{
    BIGNUM *x, *y, *k, *nsum;
    int offset, itemsize, ret = 0;
    EC_POINT *K;
    unsigned char *ptr, *tmp, keyseed[SHA256_DIGEST_LENGTH], kckpmk[(SHA256_DIGEST_LENGTH * 2) * 8];
    HMAC_CTX ctx;

    /*
     * check whether the frame is big enough (might be proprietary IEs or cruft appended)
     */
    if (len < (IEEE802_11_HDR_LEN + sizeof(frame->authenticate) +
                (2 * BN_num_bytes(peer->grp_def->prime)) + BN_num_bytes(peer->grp_def->order))) {
        sae_debug(SAE_DEBUG_ERR, "invalid size for commit message (%d < %d+%d+(2*%d)+%d = %d))\n", len,
                  IEEE802_11_HDR_LEN, sizeof(frame->authenticate), BN_num_bytes(peer->grp_def->prime),
                  BN_num_bytes(peer->grp_def->order),
                  (IEEE802_11_HDR_LEN+sizeof(frame->authenticate)+
                   (2*BN_num_bytes(peer->grp_def->prime)) + BN_num_bytes(peer->grp_def->order)));
        return -1;
    }
    if (((x = BN_new()) == NULL) ||
        ((y = BN_new()) == NULL) ||
        ((k = BN_new()) == NULL) ||
        ((K = EC_POINT_new(peer->grp_def->group)) == NULL)) {
        sae_debug(SAE_DEBUG_ERR, "unable to create x,y bignums\n");
        return -1;
    }
    ptr = frame->authenticate.u.var8;
    /*
     * first thing in a commit is the finite cyclic group, skip the group
     */
    ptr += sizeof(unsigned short);

    if (peer->got_token) {
        /*
         * if we got a token then skip over it. We know the size because we
         * created it in the first place!
         */
        ptr += SHA256_DIGEST_LENGTH;
    }

    /*
     * first get the peer's scalar
     */
    itemsize = BN_num_bytes(peer->grp_def->order);
    BN_bin2bn(ptr, itemsize, peer->peer_scalar);
    ptr += itemsize;
    /*
     * then get x and y and turn them into the peer's element
     */
    itemsize = BN_num_bytes(peer->grp_def->prime);
    BN_bin2bn(ptr, itemsize, x);
    ptr += itemsize;
    BN_bin2bn(ptr, itemsize, y);

    if (!EC_POINT_set_affine_coordinates_GFp(peer->grp_def->group, peer->peer_element, x, y, bnctx)) {
        sae_debug(SAE_DEBUG_ERR, "unable to obtain peer's password element!\n");
        goto fail;
    }

    /*
     * validate the scalar...
     */
    if ((BN_cmp(peer->peer_scalar, BN_value_one()) < 1) ||
        (BN_cmp(peer->peer_scalar, peer->grp_def->order) > 0)) {
        sae_debug(SAE_DEBUG_ERR, "peer's scalar is invalid!\n");
        goto fail;
    }
    /*
     * ...and the element
     */
    if (!EC_POINT_is_on_curve(peer->grp_def->group, peer->peer_element, bnctx)) {
        sae_debug(SAE_DEBUG_ERR, "peer's element is invalid!\n");
        goto fail;
    }

    if (sae_debug_mask & SAE_DEBUG_CRYPTO_VERB) {
        printf("peer's commit:\n");
        pp_a_bignum("peer's scalar", peer->peer_scalar);
        printf("peer's element:\n");
        pp_a_bignum("x", x);
        pp_a_bignum("y", y);
    }

    /*
     * now compute: scalar * PWE...
     */
    if (!EC_POINT_mul(peer->grp_def->group, K, NULL, peer->pwe, peer->peer_scalar, bnctx)) {
        sae_debug(SAE_DEBUG_ERR, "unable to multiply peer's scalar and PWE!\n");
        goto fail;
    }

    /*
     * ... + element
     */
    if (!EC_POINT_add(peer->grp_def->group, K, K, peer->peer_element, bnctx)) {
        sae_debug(SAE_DEBUG_ERR, "unable to add element to running point!\n");
        goto fail;
    }
    /*
     * ... * private val = our private_val * peer's private_val * pwe
     */
    if (!EC_POINT_mul(peer->grp_def->group, K, NULL, K, peer->private_val, bnctx)) {
        sae_debug(SAE_DEBUG_ERR, "unable to multiple intermediate by private value!\n");
        goto fail;
    }

    if (!EC_POINT_get_affine_coordinates_GFp(peer->grp_def->group, K, k, NULL, bnctx)) {
        sae_debug(SAE_DEBUG_ERR, "unable to get secret key!\n");
        goto fail;
    }

    /*
     * compute the KCK and PMK
     */
    if ((tmp = (unsigned char *)malloc(BN_num_bytes(peer->grp_def->prime))) == NULL) {
        sae_debug(SAE_DEBUG_ERR, "unable to malloc %d bytes for secret!\n",
                  BN_num_bytes(k));
        goto fail;
    }
    /*
     * first extract the entropy from k into keyseed...
     */
    offset = BN_num_bytes(peer->grp_def->prime) - BN_num_bytes(k);
    memset(tmp, 0, offset);
    BN_bn2bin(k, tmp + offset);
    H_Init(&ctx, allzero, SHA256_DIGEST_LENGTH);
    H_Update(&ctx, tmp, BN_num_bytes(peer->grp_def->prime));
    H_Final(&ctx, keyseed);
    free(tmp);

    /*
     * ...then expand it to create KCK | PMK
     */
    if (((tmp = (unsigned char *)malloc(BN_num_bytes(peer->grp_def->order))) == NULL) ||
        ((nsum = BN_new()) == NULL)) {
        sae_debug(SAE_DEBUG_ERR, "unable to create buf/bignum to sum scalars!\n");
        goto fail;
    }
    BN_add(nsum, peer->my_scalar, peer->peer_scalar);
    BN_mod(nsum, nsum, peer->grp_def->order, bnctx);
    offset = BN_num_bytes(peer->grp_def->order) - BN_num_bytes(nsum);
    memset(tmp, 0, offset);
    BN_bn2bin(nsum, tmp + offset);

    memcpy(peer->pmkid, tmp, 16);

    prf(keyseed, SHA256_DIGEST_LENGTH,
        (unsigned char *)"SAE KCK and PMK", strlen("SAE KCK and PMK"),
        tmp, BN_num_bytes(peer->grp_def->order),
        kckpmk, ((SHA256_DIGEST_LENGTH * 2) * 8));
    free(tmp);
    BN_free(nsum);

    memcpy(peer->kck, kckpmk, SHA256_DIGEST_LENGTH);
    memcpy(peer->pmk, kckpmk+SHA256_DIGEST_LENGTH, SHA256_DIGEST_LENGTH);

    if (sae_debug_mask & SAE_DEBUG_CRYPTO_VERB) {
        pp_a_bignum("k", k);
        print_buffer("keyseed", keyseed, SHA256_DIGEST_LENGTH);
        print_buffer("KCK", peer->kck, SHA256_DIGEST_LENGTH);
        print_buffer("PMK", peer->pmk, SHA256_DIGEST_LENGTH);
    }
    if (0) {
fail:
        ret = -1;
    }
    BN_free(x);
    BN_free(y);
    BN_free(k);
    EC_POINT_free(K);

    return ret;
}

static int
commit_to_peer (struct candidate *peer, unsigned char *token, int token_len)
{
    char buf[2048];
    struct ieee80211_mgmt_frame *frame;
    int offset1, offset2;
    size_t len = 0;
    BIGNUM *x, *y, *mask;
    unsigned short grp_num;
    unsigned char *ptr;

    memset(buf, 0, sizeof(buf));
    frame = (struct ieee80211_mgmt_frame *)buf;

    /*
     * fill in authentication frame header...
     */
    frame->frame_control = ieee_order((IEEE802_11_FC_TYPE_MGMT << 2 | IEEE802_11_FC_STYPE_AUTH << 4));
    memcpy(frame->sa, peer->my_mac, ETH_ALEN);
    memcpy(frame->da, peer->peer_mac, ETH_ALEN);
    memcpy(frame->bssid, peer->peer_mac, ETH_ALEN);

    frame->authenticate.alg = ieee_order(SAE_AUTH_ALG);
    frame->authenticate.auth_seq = ieee_order(SAE_AUTH_COMMIT);
    len = IEEE802_11_HDR_LEN + sizeof(frame->authenticate);
    ptr = frame->authenticate.u.var8;

    /*
     * first, indicate what group we're committing with
     */
    grp_num = ieee_order(peer->grp_def->group_num);
    memcpy(ptr, &grp_num, sizeof(unsigned short));
    ptr += sizeof(unsigned short);
    len += sizeof(unsigned short);

    /*
     * if we've been asked to include a token then include a token
     */
    if (token_len && (token != NULL)) {
        memcpy(ptr, token, token_len);
        ptr += token_len;
        len += token_len;
    }

    if (peer->private_val == NULL) {
        if (((mask = BN_new()) == NULL) ||
            ((peer->private_val = BN_new()) == NULL)) {
            sae_debug(SAE_DEBUG_ERR, "unable to commit to peer!\n");
            return -1;
        }
        /*
         * generate private values
         */
        BN_rand_range(peer->private_val, peer->grp_def->order);
        BN_rand_range(mask, peer->grp_def->order);
        if (sae_debug_mask & SAE_DEBUG_CRYPTO_VERB) {
            pp_a_bignum("local private value", peer->private_val);
            pp_a_bignum("local mask value", mask);
        }
        /*
         * generate scalar = (priv + mask) mod order
         */
        BN_add(peer->my_scalar, peer->private_val, mask);
        BN_mod(peer->my_scalar, peer->my_scalar, peer->grp_def->order, bnctx);
        /*
         * generate element = -(mask*pwe)
         */
        if (!EC_POINT_mul(peer->grp_def->group, peer->my_element, NULL, peer->pwe, mask, bnctx)) {
            sae_debug(SAE_DEBUG_ERR, "unable to compute A!\n");
            BN_free(mask);
            return -1;
        }
        if (!EC_POINT_invert(peer->grp_def->group, peer->my_element, bnctx)) {
            sae_debug(SAE_DEBUG_ERR, "unable to invert A!\n");
            BN_free(mask);
            return -1;
        }
        BN_free(mask);
    }
    if (((x = BN_new()) == NULL) ||
        ((y = BN_new()) == NULL)) {
        sae_debug(SAE_DEBUG_ERR, "unable to create x,y bignums\n");
        return -1;
    }
    if (!EC_POINT_get_affine_coordinates_GFp(peer->grp_def->group, peer->my_element, x, y, bnctx)) {
        sae_debug(SAE_DEBUG_ERR, "unable to get secret key!\n");
        BN_free(x);
        BN_free(y);
        return -1;
    }
    if (sae_debug_mask & SAE_DEBUG_CRYPTO_VERB) {
        printf("local commit:\n");
        pp_a_bignum("my scalar", peer->my_scalar);
        printf("my element:\n");
        pp_a_bignum("x", x);
        pp_a_bignum("y", y);
    }
    /*
     * fill in the commit, first in the commit message is the scalar
     */
    offset1 = BN_num_bytes(peer->grp_def->order) - BN_num_bytes(peer->my_scalar);
    BN_bn2bin(peer->my_scalar, ptr + offset1);
    ptr += BN_num_bytes(peer->grp_def->order);
    len += BN_num_bytes(peer->grp_def->order);

    /*
     * ...next is the element, x then y
     */
    if (!EC_POINT_get_affine_coordinates_GFp(peer->grp_def->group, peer->my_element, x, y, bnctx)) {
        sae_debug(SAE_DEBUG_ERR, "unable to determine u!\n");
        exit(1);
    }
    offset1 = BN_num_bytes(peer->grp_def->prime) - BN_num_bytes(x);
    BN_bn2bin(x, ptr + offset1);
    ptr += BN_num_bytes(peer->grp_def->prime);

    offset2 = BN_num_bytes(peer->grp_def->prime) - BN_num_bytes(y);
    BN_bn2bin(y, ptr + offset2);
    ptr += BN_num_bytes(peer->grp_def->prime);

    len += (2 * BN_num_bytes(peer->grp_def->prime));

    sae_debug(SAE_DEBUG_PROTOCOL_MSG, "in %s, sending %s (%s token), len %d, group %d\n",
              state_to_string(peer->state),
              seq_to_string(ieee_order(frame->authenticate.auth_seq)),
              (token_len ? "with" : "no"), len,
              peer->grp_def->group_num);
    BN_free(x);
    BN_free(y);
    if (meshd_write_mgmt(buf, len, peer->cookie) != len) {
        sae_debug(SAE_DEBUG_ERR, "can't send an authentication frame to " MACSTR "\n",
                  MAC2STR(peer->peer_mac));
        return -1;
    }

    return 0;
}

static int
request_token (struct ieee80211_mgmt_frame *req, unsigned char *me, void *cookie)
{
    char buf[2048];
    struct ieee80211_mgmt_frame *frame;
    HMAC_CTX ctx;
    size_t len = 0;

    memset(buf, 0, sizeof(buf));
    frame = (struct ieee80211_mgmt_frame *)buf;

    frame->frame_control = ieee_order((IEEE802_11_FC_TYPE_MGMT << 2 | IEEE802_11_FC_STYPE_AUTH << 4));
    memcpy(frame->sa, me, ETH_ALEN);
    memcpy(frame->da, req->sa, ETH_ALEN);
    memcpy(frame->bssid, req->sa, ETH_ALEN);

    frame->authenticate.alg = req->authenticate.alg;
    frame->authenticate.auth_seq = ieee_order(SAE_AUTH_COMMIT);
    frame->authenticate.status = ieee_order(WLAN_STATUS_ANTI_CLOGGING_TOKEN_NEEDED);
    len = IEEE802_11_HDR_LEN + sizeof(frame->authenticate);

    H_Init(&ctx, (unsigned char *)&token_generator, sizeof(unsigned long));
    H_Update(&ctx, req->sa, ETH_ALEN);
    H_Update(&ctx, me, ETH_ALEN);
    H_Final(&ctx, frame->authenticate.u.var8);
    len += SHA256_DIGEST_LENGTH;

    sae_debug(SAE_DEBUG_PROTOCOL_MSG, "sending a token request to " MACSTR "\n", MAC2STR(req->sa));
    if (meshd_write_mgmt(buf, len, cookie) != len) {
        sae_debug(SAE_DEBUG_ERR, "can't send a rejection frame to " MACSTR "\n",
                MAC2STR(req->sa));
        return -1;
    }
    return len;
}

static int
reject_to_peer (struct candidate *peer, struct ieee80211_mgmt_frame *frame)
{
    char buf[2048];
    struct ieee80211_mgmt_frame *rej;
    size_t len = 0;

    memset(buf, 0, sizeof(buf));
    rej = (struct ieee80211_mgmt_frame *)buf;

    rej->frame_control = ieee_order((IEEE802_11_FC_TYPE_MGMT << 2 | IEEE802_11_FC_STYPE_AUTH << 4));
    memcpy(rej->sa, peer->my_mac, ETH_ALEN);
    memcpy(rej->da, peer->peer_mac, ETH_ALEN);
    memcpy(rej->bssid, peer->peer_mac, ETH_ALEN);

    rej->authenticate.alg = frame->authenticate.alg;    /* no need for order conversion */
    rej->authenticate.auth_seq = ieee_order(SAE_AUTH_COMMIT);
    rej->authenticate.status = ieee_order(WLAN_STATUS_NOT_SUPPORTED_GROUP);
    len = IEEE802_11_HDR_LEN + sizeof(rej->authenticate);

    /*
     * indicate what we're rejecting
     */
    memcpy(rej->authenticate.u.var8, frame->authenticate.u.var8, sizeof(unsigned long));
    len += sizeof(unsigned long);

    sae_debug(SAE_DEBUG_PROTOCOL_MSG, "sending REJECTION to " MACSTR "\n", MAC2STR(peer->peer_mac));
    if (meshd_write_mgmt(buf, len, peer->cookie) != len) {
        sae_debug(SAE_DEBUG_ERR, "can't send an authentication frame to " MACSTR "\n",
                MAC2STR(peer->peer_mac));
        return -1;
    }

    return 0;
}

/*
 * assign_group_tp_peer()
 *      The group has been selected, assign it to the peer and create PWE.
 */
static int
assign_group_to_peer (struct candidate *peer, GD *grp)
{
    HMAC_CTX ctx;
    BIGNUM *x_candidate = NULL, *rnd = NULL;
    unsigned char pwe_digest[SHA256_DIGEST_LENGTH], *prfbuf, ctr, *primebuf, addrs[ETH_ALEN * 2];
    int primebitlen, is_odd;

    /*
     * allow for replacement of group....
     */
    EC_POINT_free(peer->pwe);
    peer->pwe = NULL;
    EC_POINT_free(peer->peer_element);
    peer->peer_element = NULL;
    EC_POINT_free(peer->my_element);
    peer->my_element = NULL;
    BN_free(peer->private_val);
    peer->private_val = NULL;

    if (((rnd = BN_new()) == NULL) ||
        ((x_candidate = BN_new()) == NULL)) {
        sae_debug(SAE_DEBUG_ERR, "can't create bignum for candidate!\n");
        BN_free(rnd);
        BN_free(x_candidate);
        return -1;
    }
    peer->grp_def = grp;
    peer->pwe = EC_POINT_new(grp->group);
    peer->peer_element = EC_POINT_new(grp->group);
    peer->my_element = EC_POINT_new(grp->group);

    if ((prfbuf = (unsigned char *)malloc(BN_num_bytes(grp->prime))) == NULL) {
        sae_debug(SAE_DEBUG_ERR, "unable to malloc space for prf buffer!\n");
        BN_free(rnd);
        BN_free(x_candidate);
        return -1;
    }
    if ((primebuf = (unsigned char *)malloc(BN_num_bytes(grp->prime))) == NULL) {
        sae_debug(SAE_DEBUG_ERR, "unable to malloc space for prime!\n");
        free(prfbuf);
        BN_free(rnd);
        BN_free(x_candidate);
        return -1;
    }
    BN_bn2bin(grp->prime, primebuf);
    primebitlen = BN_num_bits(grp->prime);
    sae_debug(SAE_DEBUG_CRYPTO, "computing PWE on %d bit curve number %d\n", primebitlen, grp->group_num);
    ctr = 0;
    while (1) {
        if (ctr > 16) {
            EC_POINT_free(peer->pwe);
            peer->pwe = NULL;
            break;
        }
        ctr++;
        /*
         * compute counter-mode password value and stretch to prime
         */
        if (memcmp(peer->peer_mac, peer->my_mac, ETH_ALEN) > 0) {
            memcpy(addrs, peer->peer_mac, ETH_ALEN);
            memcpy(addrs+ETH_ALEN, peer->my_mac, ETH_ALEN);
        } else {
            memcpy(addrs, peer->my_mac, ETH_ALEN);
            memcpy(addrs+ETH_ALEN, peer->peer_mac, ETH_ALEN);
        }
        H_Init(&ctx, addrs, (ETH_ALEN * 2));
        H_Update(&ctx, (unsigned char *) grp->password, strlen(grp->password));
        H_Update(&ctx, &ctr, sizeof(ctr));
        H_Final(&ctx, pwe_digest);

        if (sae_debug_mask & SAE_DEBUG_CRYPTO_VERB) {
            if (memcmp(peer->peer_mac, peer->my_mac, ETH_ALEN) > 0) {
                printf("H(" MACSTR " | " MACSTR ", %s | %d)\n",
                       MAC2STR(peer->peer_mac), MAC2STR(peer->my_mac), grp->password, ctr);
            } else {
                printf("H(" MACSTR " | " MACSTR ", %s | %d)\n",
                       MAC2STR(peer->my_mac), MAC2STR(peer->peer_mac), grp->password, ctr);
            }
            dump_buffer(pwe_digest, SHA256_DIGEST_LENGTH);
        }

        BN_bin2bn(pwe_digest, SHA256_DIGEST_LENGTH, rnd);
        prf(pwe_digest, SHA256_DIGEST_LENGTH,
            (unsigned char *)"SAE Hunting and Pecking", strlen("SAE Hunting and Pecking"),
            primebuf, BN_num_bytes(grp->prime),
            prfbuf, primebitlen);
        BN_bin2bn(prfbuf, BN_num_bytes(grp->prime), x_candidate);
        /*
         * prf() returns a string of bits 0..primebitlen, but BN_bin2bn will
         * treat that string of bits as a big-endian number. If the primebitlen
         * is not an even multiple of 8 we masked off the excess bits-- those
         * _after_ primebitlen-- in prf() so now interpreting this as a
         * big-endian number is wrong. We have to shift right the amount we
         * masked off.
         */
        if (primebitlen % 8) {
            BN_rshift(x_candidate, x_candidate, (8 - (primebitlen % 8)));
        }

        /*
         * if this candidate value is greater than the prime then try again
         */
        if (BN_ucmp(x_candidate, grp->prime) >= 0) {
            continue;
        }

        if (sae_debug_mask & SAE_DEBUG_CRYPTO_VERB) {
            memset(prfbuf, 0, BN_num_bytes(grp->prime));
            BN_bn2bin(x_candidate, prfbuf + (BN_num_bytes(grp->prime) - BN_num_bytes(x_candidate)));
            print_buffer("candidate x value", prfbuf, BN_num_bytes(grp->prime));
        }

        /*
         * need to unambiguously identify the solution, if there is one...
         */
        if (BN_is_odd(rnd)) {
            is_odd = 1;
        } else {
            is_odd = 0;
        }
        /*
         * solve the quadratic equation, if it's not solvable then we
         * don't have a point
         */
        if (!EC_POINT_set_compressed_coordinates_GFp(grp->group, peer->pwe, x_candidate, is_odd, bnctx)) {
            sae_debug(SAE_DEBUG_CRYPTO_VERB, "no solution for random x, ctr = %d...\n", ctr);
            continue;
        }
        /*
         * If there's a solution to the equation then the point must be on
         * the curve so why check again explicitly? OpenSSL code says this
         * is required by X9.62. We're not X9.62 but it can't hurt just to
         * be sure.
         */
        if (!EC_POINT_is_on_curve(grp->group, peer->pwe, bnctx)) {
            sae_debug(SAE_DEBUG_CRYPTO_VERB, "point is not on curve! ctr = %d\n", ctr);
            continue;
        }

        /*
         * if we got here then we have PWE!
         */
        break;
    }

    if (sae_debug_mask & SAE_DEBUG_CRYPTO_VERB) {
        BIGNUM *px = NULL, *py = NULL;
        if (((px = BN_new()) != NULL) &&
            ((py = BN_new()) != NULL)) {
            if (EC_POINT_get_affine_coordinates_GFp(peer->grp_def->group, peer->pwe, px, py, bnctx)) {
                printf("PWE (x,y):\n");
                memset(prfbuf, 0, BN_num_bytes(grp->prime));
                BN_bn2bin(px, prfbuf + (BN_num_bytes(grp->prime) - BN_num_bytes(px)));
                print_buffer("x", prfbuf, BN_num_bytes(grp->prime));
                memset(prfbuf, 0, BN_num_bytes(grp->prime));
                BN_bn2bin(py, prfbuf + (BN_num_bytes(grp->prime) - BN_num_bytes(py)));
                print_buffer("y", prfbuf, BN_num_bytes(grp->prime));
            }
            BN_free(px);
            BN_free(py);
        }
    }

    free(prfbuf);
    free(primebuf);
    BN_free(x_candidate);
    BN_free(rnd);

    if (peer->pwe == NULL) {
        sae_debug(SAE_DEBUG_ERR, "unable to find random point on curve for group %d, something's fishy!\n",
                  grp->group_num);
        return -1;
    }
    sae_debug(SAE_DEBUG_CRYPTO, "it took %d tries to find PWE: %d\n", ctr, grp->group_num);

    sae_debug(SAE_DEBUG_PROTOCOL_MSG, "assigning group %d to peer, the size of the prime is %d\n",
              peer->grp_def->group_num, BN_num_bytes(peer->grp_def->prime));

    return 0;
}

static void
retransmit_peer (timerid id, void *data)
{
    struct candidate *peer;

    peer = (struct candidate *)data;
    sae_debug(SAE_DEBUG_STATE_MACHINE, "timer %d fired! retrans = %d, incrementing\n", peer->t0, peer->sync);
    if (peer->sync > giveup_threshold) {
        sae_debug(SAE_DEBUG_STATE_MACHINE, "peer not listening!\n");
        if (peer->state == SAE_COMMITTED) {
            /*
             * if the peer never responded then put it on the blacklist for a while
             */
            sae_debug(SAE_DEBUG_STATE_MACHINE, MACSTR " never responded, adding to blacklist\n", MAC2STR(peer->peer_mac));
            blacklist_peer(peer);
        }
        fin(WLAN_STATUS_AUTHENTICATION_TIMEOUT, peer->peer_mac, NULL, 0, peer->cookie);
        delete_peer(&peer);
        return;
    }
    peer->sync++;
    switch (peer->state) {
        case SAE_COMMITTED:
            commit_to_peer(peer, NULL, 0);
            peer->t0 = srv_add_timeout(srvctx, SRV_SEC(retrans), retransmit_peer, peer);
            break;
        case SAE_CONFIRMED:
            confirm_to_peer(peer);
            peer->t0 = srv_add_timeout(srvctx, SRV_SEC(retrans), retransmit_peer, peer);
            break;
        default:
            sae_debug(SAE_DEBUG_STATE_MACHINE, "timer fired and not committed or confirmed!\n");
            break;
    }
}

struct candidate *
create_candidate (unsigned char *her_mac, unsigned char *my_mac, unsigned short got_token, void *cookie)
{
    struct candidate *peer;

    if ((peer = (struct candidate *)malloc(sizeof(struct candidate))) == NULL) {
        sae_debug(SAE_DEBUG_ERR, "can't malloc space for candidate!\n");
        return NULL;
    }
    memset(peer, 0, sizeof(*peer));
    memcpy(peer->my_mac, my_mac, ETH_ALEN);
    memcpy(peer->peer_mac, her_mac, ETH_ALEN);
    if (((peer->peer_scalar = BN_new()) == NULL) ||
        ((peer->my_scalar = BN_new()) == NULL)) {
        sae_debug(SAE_DEBUG_ERR, "can't create peer data structures!\n");
        free(peer);
        return NULL;
    }
    peer->got_token = got_token;
    peer->failed_auth = peer->beacons = peer->state = peer->sync = peer->sc = peer->rc = 0;
    peer->private_val = NULL;
    peer->pwe = peer->peer_element = peer->my_element = NULL;
    TAILQ_INSERT_TAIL(&peers, peer, entry);
    peer->state = SAE_NOTHING;
    peer->cookie = cookie;
    curr_open++;

    peer_created(her_mac);

    return peer;
}

static void
reauth (timerid id, void *data)
{
    struct candidate *peer, *newpeer;

    peer = (struct candidate *)data;
    if ((newpeer = create_candidate(peer->peer_mac, peer->my_mac, 0, peer->cookie)) != NULL) {
        if (assign_group_to_peer(newpeer, gd) < 0) {
            delete_peer(&newpeer);
        } else {
            commit_to_peer(newpeer, NULL, 0);
            newpeer->t0 = srv_add_timeout(srvctx, SRV_SEC(retrans), retransmit_peer, newpeer);
            newpeer->state = SAE_COMMITTED;
        }
    }
    /*
     * make a hard deletion of this guy in case the reauth fails and we
     * don't end up deleting this instance
     */
    peer->t1 = srv_add_timeout(srvctx, SRV_SEC(5), destroy_peer, peer);
}

static enum result
process_authentication_frame (struct candidate *peer, struct ieee80211_mgmt_frame *frame, int len)
{
    unsigned short grp;
    unsigned short seq = ieee_order(frame->authenticate.auth_seq);
    unsigned short status = ieee_order(frame->authenticate.status);
    GD *group_def;
    struct candidate *delme;
    enum result ret;

    sae_debug(SAE_DEBUG_PROTOCOL_MSG, "recv'd %s from " MACSTR " while in %s\n",
              seq_to_string(seq), MAC2STR(frame->sa),
              state_to_string(peer->state));

    srv_rem_timeout(srvctx, peer->t0);
    /*
     * implement the state machine for SAE
     */
    switch (peer->state) {
        case SAE_NOTHING:
            switch (seq) {
                case SAE_AUTH_COMMIT:
                    /*
                     * if the status is anything other than 0 then throw this away
                     * since as far as we're concerned this is unsolicited and there's
                     * no error we committed.
                     */
                    if (status != 0) {
                        return ERR_FATAL;
                    }
                    /*
                     * grab the group from the frame...
                     */
                    grp = ieee_order(*((frame->authenticate.u.var16)));
                    /*
                     * ...and see if it's supported
                     */
                    group_def = gd;
                    while (group_def) {
                        if (grp == group_def->group_num) {
                            if (assign_group_to_peer(peer, group_def) < 0) {
                                return ERR_FATAL;
                            }
                            break;
                        }
                        group_def = group_def->next;
                    }
                    if (group_def == NULL) {
                        /*
                         * send a rejection to the peer and a "del" event to the parent
                         */
                        sae_debug(SAE_DEBUG_STATE_MACHINE, "group %d not supported, reject.\n", grp);
                        reject_to_peer(peer, frame);
                        return ERR_FATAL;
                    }
                    sae_debug(SAE_DEBUG_STATE_MACHINE, "COMMIT received for unknown peer, committing and confirming\n");
                    peer->sc = peer->rc = 0;
                    commit_to_peer(peer, NULL, 0);
                    if (process_commit(peer, frame, len) < 0) {
                        return ERR_FATAL;
                    }
                    /*
                     * send both a commit and a confirm and transition into confirmed
                     */
                    confirm_to_peer(peer);
                    peer->sync = 0;
                    peer->t0 = srv_add_timeout(srvctx, SRV_SEC(retrans), retransmit_peer, peer);
                    peer->state = SAE_CONFIRMED;
                    break;
                case SAE_AUTH_CONFIRM:
                    return ERR_FATAL;
                default:
                    sae_debug(SAE_DEBUG_ERR, "unknown SAE frame (%d) from " MACSTR "\n",
                           seq, MAC2STR(peer->peer_mac));
                    return ERR_NOT_FATAL;
            }
            break;
        case SAE_COMMITTED:
            switch (seq) {
                case SAE_AUTH_COMMIT:
                    /*
                     * if it's an anti-clogging token request, send another
                     * commit with the token.
                     *
                     * Increment the sync counter, the spec doesn't say so but this
                     * guards against bad implementations.
                     */
                    if (status == WLAN_STATUS_ANTI_CLOGGING_TOKEN_NEEDED) {
                        sae_debug(SAE_DEBUG_STATE_MACHINE,
                                  "received a token request, add a token, length %d, and resend commit\n",
                                  (len - (IEEE802_11_HDR_LEN + sizeof(frame->authenticate))));
                        commit_to_peer(peer, frame->authenticate.u.var8,
                                       (len - (IEEE802_11_HDR_LEN + sizeof(frame->authenticate))));
                        peer->sync = 0;
                        peer->t0 = srv_add_timeout(srvctx, SRV_SEC(retrans), retransmit_peer, peer);
                        break;
                    }
                    /*
                     * grab the group from the frame, we need it later
                     */
                    grp = ieee_order(*((frame->authenticate.u.var16)));
                    if (status == WLAN_STATUS_NOT_SUPPORTED_GROUP) {
                        /*
                         * if it's a rejection check whether it's what we sent.
                         * If so try another configured group.
                         */
                        if (grp == peer->grp_def->group_num) {
                            /*
                             * if there's no more configured groups to offer then just declare failure,
                             * blacklist the client since we cannot currently communicate.
                             */
                            if (peer->grp_def->next == NULL) {
                                return ERR_BLACKLIST;
                            }
                            /*
                             * otherwise assign the next group and send another commit
                             */
                            group_def = peer->grp_def->next;
                            sae_debug(SAE_DEBUG_STATE_MACHINE, "peer rejected %d, try group %d instead...\n",
                                      peer->grp_def->group_num, group_def->group_num);
                            assign_group_to_peer(peer, group_def);
                            commit_to_peer(peer, NULL, 0);
                            peer->sync = 0;
                        } else {
                            sae_debug(SAE_DEBUG_STATE_MACHINE,
                                      "peer is rejecting something (%d) not offered, must be old, ignore...\n", grp);
                        }
                        peer->t0 = srv_add_timeout(srvctx, SRV_SEC(retrans), retransmit_peer, peer);
                        break;
                    }
                    /*
                     * silently drop any other failure
                     */
                    if (status != 0) {
                        peer->t0 = srv_add_timeout(srvctx, SRV_SEC(retrans), retransmit_peer, peer);
                        break;
                    }
                    /*
                     * if the group offered is not the same as what we offered
                     * that means the commit messages crossed in the ether. Check
                     * whether this is something we can support and if so tie break.
                     */
                    if (grp != peer->grp_def->group_num) {
                        group_def = gd;
                        while (group_def) {
                            if (grp == group_def->group_num) {
                                break;
                            }
                            group_def = group_def->next;
                        }
                        /*
                         * nope, not supported, send rejection
                         */
                        if (group_def == NULL) {
                            if (peer->sync > giveup_threshold) {
                                return ERR_FATAL;
                            }
                            sae_debug(SAE_DEBUG_STATE_MACHINE, "group %d not supported, send rejection\n", grp);
                            peer->sync++;
                            reject_to_peer(peer, frame);
                            peer->t0 = srv_add_timeout(srvctx, SRV_SEC(retrans), retransmit_peer, peer);
                            break;
                        }
                        /*
                         * OK, this is not what we offered but it's aceptable...
                         */
                        if (memcmp(peer->my_mac, peer->peer_mac, ETH_ALEN) > 0) {
                            sae_debug(SAE_DEBUG_STATE_MACHINE,
                                      "offered group %d, got %d in return, numerically greater, maintain.\n",
                                      peer->grp_def->group_num, grp);

                            /*
                             * the numerically greater MAC address retransmits
                             */
                            commit_to_peer(peer, NULL, 0);
                            peer->t0 = srv_add_timeout(srvctx, SRV_SEC(retrans), retransmit_peer, peer);
                            break;
                        } else {
                            sae_debug(SAE_DEBUG_STATE_MACHINE,
                                      "offered group %d, got %d in return, numerically lesser, submit.\n",
                                      peer->grp_def->group_num, grp);
                            /*
                             * the numerically lesser converts, send a commit with
                             * this group and then just proceed with the acceptable
                             * commit
                             */
                            peer->sync = 0;
                            assign_group_to_peer(peer, group_def);
                            commit_to_peer(peer, NULL, 0);
                            if (process_commit(peer, frame, len) < 0) {
                                return ERR_FATAL;
                            }
                        }
                    } else {
                        /*
                         * else it's the group we offered, check for a reflection attack,
                         * and if not then process the frame
                         */
                        if (check_dup(peer, 1, frame, len) == 0) {
                            return NO_ERR;      /* silently discard */
                        }
                        if (process_commit(peer, frame, len) < 0) {
                            return ERR_FATAL;
                        }
                    }
                    confirm_to_peer(peer);
                    peer->t0 = srv_add_timeout(srvctx, SRV_SEC(retrans), retransmit_peer, peer);
                    peer->state = SAE_CONFIRMED;
                    break;
                case SAE_AUTH_CONFIRM:
                    sae_debug(SAE_DEBUG_STATE_MACHINE, "got CONFIRM before COMMIT, try again\n");
                    if (peer->sync > giveup_threshold) {
                        return ERR_FATAL;
                    }
                    peer->sync++;
                    commit_to_peer(peer, NULL, 0);
                    peer->t0 = srv_add_timeout(srvctx, SRV_SEC(retrans), retransmit_peer, peer);
                    break;
                default:
                    sae_debug(SAE_DEBUG_ERR, "unknown SAE frame (%d) from " MACSTR "\n",
                              seq, MAC2STR(peer->peer_mac));
                    return ERR_NOT_FATAL;
            }
            break;
        case SAE_CONFIRMED:
            if (status != 0) {
                /*
                 * silently discard, but since we cancelled the timer above, reset it
                 */
                peer->t0 = srv_add_timeout(srvctx, SRV_SEC(retrans), retransmit_peer, peer);
                break;
            }
            switch (seq) {
                case SAE_AUTH_COMMIT:
                    if (peer->sync > giveup_threshold) {
                        return ERR_FATAL;
                    }
                    grp = ieee_order(*(frame->authenticate.u.var16));
                    if (grp == peer->grp_def->group_num) {
                        sae_debug(SAE_DEBUG_STATE_MACHINE, "got COMMIT again, try to resync\n");
                        peer->sync++;
                        commit_to_peer(peer, NULL, 0);
                        confirm_to_peer(peer);
                    }
                    peer->t0 = srv_add_timeout(srvctx, SRV_SEC(retrans), retransmit_peer, peer);
                    break;
                case SAE_AUTH_CONFIRM:
                    ret = process_confirm(peer, frame, len);
                    switch (ret) {
                        case ERR_FATAL:
                        case ERR_BLACKLIST:
                            sae_debug(SAE_DEBUG_STATE_MACHINE, "Delete event received from protocol instance for " MACSTR "\n",
                                      MAC2STR(peer->peer_mac));
                            return ret;
                        case ERR_NOT_FATAL:                   /* this is not in 11s draft */
                            peer->sync++;
                            confirm_to_peer(peer);
                            return NO_ERR;
                        case NO_ERR:
                            break;
                    }
                    curr_open--;
                    peer->sc = COUNTER_INFINITY;
                    if ((delme = find_peer(peer->peer_mac, 1)) != NULL) {
                        sae_debug(SAE_DEBUG_STATE_MACHINE,
                                  "peer in %s has just ACCEPTED, found another in %s, deleting\n",
                                  state_to_string(peer->state), state_to_string(delme->state));
                        delete_peer(&delme);
                    }
                    /*
                     * print out the PMK if we have debugging on for that
                     */
                    if (peer->state != SAE_ACCEPTED) {
                        if (sae_debug_mask & SAE_DEBUG_CRYPTO) {
                            print_buffer("PMK", peer->pmk, SHA256_DIGEST_LENGTH);
                        }
                        fin(WLAN_STATUS_SUCCESSFUL, peer->peer_mac, peer->pmk, SHA256_DIGEST_LENGTH, peer->cookie);
                    }
                    sae_debug(SAE_DEBUG_PROTOCOL_MSG, "setting reauth timer for %d seconds\n", pmk_expiry);
                    peer->t1 = srv_add_timeout(srvctx, SRV_SEC(pmk_expiry), reauth, peer);
                    peer->state = SAE_ACCEPTED;
                    break;
                default:
                    sae_debug(SAE_DEBUG_ERR, "unknown SAE frame (%d) from " MACSTR "\n",
                              seq, MAC2STR(peer->peer_mac));
                    return ERR_NOT_FATAL;
            }
            break;
        case SAE_ACCEPTED:
            switch (seq) {
                case SAE_AUTH_COMMIT:
                    /*
                     * something stinks in state machine land...
                     */
                    break;
                case SAE_AUTH_CONFIRM:
                    if (peer->sync > giveup_threshold) {
                        sae_debug(SAE_DEBUG_STATE_MACHINE, "too many syncronization errors on " MACSTR ", deleting\n",
                                  MAC2STR(peer->peer_mac));
                        return ERR_FATAL;
                    }
                    /*
                     * must've lost our confirm, check if it's old or invalid,
                     * if neither send confirm again....
                     */
                    if (check_confirm(peer, frame) &&
                        (process_confirm(peer, frame, len) >= 0)) {
                        sae_debug(SAE_DEBUG_STATE_MACHINE, "resending CONFIRM...\n");
                        peer->sync++;
                        confirm_to_peer(peer);
                    }
                    break;
                default:
                    sae_debug(SAE_DEBUG_ERR, "unknown SAE frame (%d) from " MACSTR "\n",
                              seq, MAC2STR(peer->peer_mac));
                    return ERR_NOT_FATAL;
            }
            break;
    }
    sae_debug(SAE_DEBUG_STATE_MACHINE, "state of " MACSTR " is now (%d) %s\n\n",
              MAC2STR(peer->peer_mac), peer->state, state_to_string(peer->state));
    return NO_ERR;
}

static int
have_token (struct ieee80211_mgmt_frame *frame, int len, unsigned char *me)
{
    unsigned short seq = ieee_order(frame->authenticate.auth_seq);
    unsigned short alg;
    unsigned char token[SHA256_DIGEST_LENGTH];
    HMAC_CTX ctx;
    GD *group_def;

    /*
     * if it's not a commit then by definition there's no token: bad
     */
    if (seq != SAE_AUTH_COMMIT) {
        sae_debug(SAE_DEBUG_PROTOCOL_MSG, "checking for token but not a commit!\n");
        return -1;
    }

    /*
     * it's a commmit so the first thing is the finite cyclic group
     */
    alg = ieee_order(*(frame->authenticate.u.var16));

    group_def = gd;
    while (group_def) {
        if (alg == group_def->group_num) {
            break;
        }
        group_def = group_def->next;
    }
    if (group_def == NULL) {
        /*
         * if the group isn't supported then there's no way we can truely
         * evaluate this frame, just check whether our token is there. If the
         * group isn't supported then at least we'll tell the peer of that fact
         * later and maybe we can come to some resolution after a few more exchanges.
         */
        if (len < (IEEE802_11_HDR_LEN + sizeof(frame->authenticate) + sizeof(unsigned short) + SHA256_DIGEST_LENGTH)) {
            sae_debug(SAE_DEBUG_PROTOCOL_MSG, "checking for token but there can't be one, too short!\n");
            /*
             * no token, ask for one
             */
            return 1;
        }
        H_Init(&ctx, (unsigned char *)&token_generator, sizeof(unsigned long));
        H_Update(&ctx, frame->sa, ETH_ALEN);
        H_Update(&ctx, me, ETH_ALEN);
        H_Final(&ctx, token);
        if (memcmp(token, (frame->authenticate.u.var8 + sizeof(unsigned short)), SHA256_DIGEST_LENGTH)) {
            /*
             * there's something there but it's not a token, so ask for one.
             *
             * should we maybe return -1 to silently drop this frame? Hmmm...
             */
             return 1;
        }
    } else {
        /*
         * The length should be the size of an authenticate frame (minus all the optional
         * fields and IEs) plus the size of the finite cyclic group field (unsigned short)
         * plus the size of the tokens we generate (SHA256_DIGEST_LEN) plus the size of
         * the order of the selected group plus twice the size of the prime of the selected
         * group (x-coordinate and y-coordinate, each the length of the prime).
         *
         * NB: if/when FFC groups are supported it won't be plus twice the prime, it'll just be
         * plus the length of the prime (an FFC element is not complex like an ECC element is).
         */
        if (len != (IEEE802_11_HDR_LEN + sizeof(frame->authenticate) + sizeof(unsigned short) +
                    SHA256_DIGEST_LENGTH + BN_num_bytes(group_def->order) +
                    (2 * BN_num_bytes(group_def->prime)))) {
            sae_debug(SAE_DEBUG_PROTOCOL_MSG,
                      "checking for token in offer of group %d but length is wrong: %d vs. %d\n",
                      group_def->group_num, len,
                      (IEEE802_11_HDR_LEN + sizeof(frame->authenticate) + sizeof(unsigned short) +
                       SHA256_DIGEST_LENGTH + BN_num_bytes(group_def->order) +
                       (2 * BN_num_bytes(group_def->prime))));
            return 1;
        }
        H_Init(&ctx, (unsigned char *)&token_generator, sizeof(unsigned long));
        H_Update(&ctx, frame->sa, ETH_ALEN);
        H_Update(&ctx, me, ETH_ALEN);
        H_Final(&ctx, token);
        if (memcmp(token, (frame->authenticate.u.var8 + sizeof(unsigned short)), SHA256_DIGEST_LENGTH)) {
            /*
             * bad token
             */
             return -1;
        }
    }
    /*
     * found a token and it's good
     */
    return 0;
}

/*
 * the "parent process" gets management frames as input and dispatches to
 * "protocol instances".
 */
int
process_mgmt_frame (struct ieee80211_mgmt_frame *frame, int len, unsigned char *me, void *cookie)
{
    unsigned short frame_control, type, auth_alg;
    int need_token;
    struct candidate *peer;
    enum result ret = ERR_FATAL;

    if (bnctx == NULL) {
        /*
         * sae_initialize() has not been called yet!
         */
        fprintf(stderr, "sae_initialize() must be called first!\n");
        return -1;
    }
    frame_control = ieee_order(frame->frame_control);
    type = IEEE802_11_FC_GET_TYPE(frame_control);
    if (type != IEEE802_11_FC_TYPE_MGMT) {
        /*
         * we should only get management frames
         */
        return -1;
    }
    /*
     * process the management frame
     */
    switch (IEEE802_11_FC_GET_STYPE(frame_control)) {
        /*
         * a beacon sort of like an "Initiate" event
         */
        case IEEE802_11_FC_STYPE_BEACON:
            /*
             * ignore blacklisted peers
             */
            if (on_blacklist(frame->sa)) {
                break;
            }
            if ((peer = find_peer(frame->sa, 0)) != NULL) {
                /*
                 * we're already dealing with this guy, ignore his beacons now
                 */
                peer->beacons++;
            } else {
                /*
                 * This is actually not part of the parent state machine but handling
                 * it here makes the rest of the protocol instance state machine nicer.
                 *
                 * a new mesh point! auth_req transitions from state "NOTHING" to "COMMITTED"
                 */
                sae_debug(SAE_DEBUG_PROTOCOL_MSG, "received a beacon from " MACSTR "\n", MAC2STR(frame->sa));
                sae_debug(SAE_DEBUG_STATE_MACHINE, "Initiate event\n");
                if ((peer = create_candidate(frame->sa, me, 0, cookie)) == NULL) {
                    return -1;
                }
                peer->cookie = cookie;
                /*
                 * assign the first group in the list as the one to try
                 */
                if (assign_group_to_peer(peer, gd) < 0) {
                    fin(WLAN_STATUS_UNSPECIFIED_FAILURE, peer->peer_mac, NULL, 0, peer->cookie);
                    delete_peer(&peer);
                } else {
                    commit_to_peer(peer, NULL, 0);
                    peer->t0 = srv_add_timeout(srvctx, SRV_SEC(retrans), retransmit_peer, peer);
                    peer->state = SAE_COMMITTED;
                    sae_debug(SAE_DEBUG_STATE_MACHINE, "state of " MACSTR " is now (%d) %s\n\n",
                              MAC2STR(peer->peer_mac), peer->state, state_to_string(peer->state));
                }
                break;
            }
            break;
        case IEEE802_11_FC_STYPE_AUTH:
            auth_alg = ieee_order(frame->authenticate.alg);
            if (auth_alg != SAE_AUTH_ALG) {
                sae_debug(SAE_DEBUG_PROTOCOL_MSG,
                          "let kernel handle authenticate (%d) frame from " MACSTR " to " MACSTR "\n",
                          auth_alg, MAC2STR(frame->sa), MAC2STR(frame->da));
                break;
            }
            peer = find_peer(frame->sa, 0);
            switch (ieee_order(frame->authenticate.auth_seq)) {
                case SAE_AUTH_COMMIT:
                    if ((peer != NULL) && (peer->state != SAE_ACCEPTED)) {
                        ret = process_authentication_frame(peer, frame, len);
                    } else {
                        /*
                         * check if this is the same scalar that was sent when we
                         * accepted.
                         */
                        if ((peer != NULL) && (peer->state == SAE_ACCEPTED)) {
                            if (check_dup(peer, 0, frame, len) == 0) {
                                return 0;
                            }
                        }
                        /*
                         * if we are currently in a token-demanding state then check for a token
                         */
                        if (!(curr_open < open_threshold)) {
                            need_token = have_token(frame, len, me);
                            if (need_token < 0) {
                                /*
                                 * silently drop nonsense frames
                                 */
                                return 0;
                            } else if (need_token > 0) {
                                /*
                                 * request a token if the frame should have one but didn't
                                 */
                                sae_debug(SAE_DEBUG_STATE_MACHINE, "token needed for COMMIT (%d open), requesting one\n",
                                          curr_open);
                                request_token(frame, me, cookie);
                                return 0;
                            } else {
                                sae_debug(SAE_DEBUG_ERR, "correct token received\n");
                            }
                        }
                        /*
                         * if we got here that means we're not demanding tokens or we are
                         * and the token was correct. In either case we create a protocol instance.
                         */
                        if ((peer = create_candidate(frame->sa, me, (curr_open >= open_threshold), cookie)) == NULL) {
                            sae_debug(SAE_DEBUG_ERR, "can't malloc space for candidate from " MACSTR "\n",
                                      MAC2STR(frame->sa));
                            return -1;
                        }
                        ret = process_authentication_frame(peer, frame, len);
                    }
                    break;
                case SAE_AUTH_CONFIRM:
                    if (peer == NULL) {
                        /*
                         * no peer instance, no way to handle this frame!
                         */
                        return 0;
                    }
                    /*
                     * since we searched above with "0" the peer we've handled the case
                     * of two peers in the db with one in ACCEPTED state already.
                     */
                    ret = process_authentication_frame(peer, frame, len);
                    break;
            }
            switch (ret) {
                case ERR_BLACKLIST:
                    /*
                     * a "del" event
                     */
                    blacklist_peer(peer);
                    fin(WLAN_STATUS_UNSPECIFIED_FAILURE, peer->peer_mac, NULL, 0, peer->cookie);
                    /* fallthru intentional */
                case ERR_FATAL:
                    /*
                     * a "fail" event, it could be argued that fin() should be done
                     * here but there are a certain class of failures-- group rejection
                     * for instance-- that don't really need fin() notification because
                     * the protocol might recover and successfully finish later.
                     */
                    delete_peer(&peer);
                    return 0;
                case ERR_NOT_FATAL:
                    /*
                     * This isn't in the 11s draft but when there is some internal error from
                     * an API call it's not really a protocol error. These things can (should?)
                     * be handled with a "fail" event but let's try and be a little more accomodating.
                     *
                     * if we get a non-fatal error return to NOTHING but don't delete yet, this way we
                     * won't try to authenticate her again when we see a beacon but will respond to an
                     * initiation from her later.
                     */
                    peer->failed_auth++;
                    peer->sync = peer->sc = peer->rc = 0;
                    peer->state = SAE_NOTHING;
                    break;
                case NO_ERR:
                    break;
            }
            if (peer->sync > giveup_threshold) {
                /*
                 * if the state machines are so out-of-whack just declare failure
                 */
                sae_debug(SAE_DEBUG_STATE_MACHINE,
                          "too many state machine syncronization errors, adding " MACSTR " to blacklist\n",
                          MAC2STR(peer->peer_mac));
                blacklist_peer(peer);
                fin(WLAN_STATUS_REQUEST_DECLINED, peer->peer_mac, NULL, 0, peer->cookie);
                delete_peer(&peer);
            }
            break;
        case IEEE802_11_FC_STYPE_ACTION:
            return process_ampe_frame(frame, len, me, cookie);
        default:
            return -1;
    }

    return 0;
}

static int
compute_group_definition (GD *grp, char *password, unsigned short num)
{
    BIGNUM *cofactor = NULL;
    int nid, ret = 0;

    switch (num) {        /* from IANA registry for IKE D-H groups */
        case 19:
            nid = NID_X9_62_prime256v1;
            break;
        case 20:
            nid = NID_secp384r1;
            break;
        case 21:
            nid = NID_secp521r1;
            break;
        case 25:
            nid = NID_X9_62_prime192v1;
            break;
        case 26:
            nid = NID_secp224r1;
            break;
        default:
            sae_debug(SAE_DEBUG_ERR, "unsupported group %d\n", num);
            return -1;
    }
    if ((grp->group = EC_GROUP_new_by_curve_name(nid)) == NULL) {
        sae_debug(SAE_DEBUG_ERR, "unable to create EC_GROUP!\n");
        return -1;
    }
    cofactor = NULL; grp->order = NULL; grp->prime = NULL;

    if (((cofactor = BN_new()) == NULL) ||
        ((grp->order = BN_new()) == NULL) ||
        ((grp->prime = BN_new()) == NULL)) {
        sae_debug(SAE_DEBUG_ERR, "unable to create bignums!\n");
        goto fail;
    }
    if (!EC_GROUP_get_curve_GFp(grp->group, grp->prime, NULL, NULL, bnctx)) {
        sae_debug(SAE_DEBUG_ERR, "unable to get prime for GFp curve!\n");
        goto fail;
    }
    if (!EC_GROUP_get_order(grp->group, grp->order, bnctx)) {
        sae_debug(SAE_DEBUG_ERR, "unable to get order for curve!\n");
        goto fail;
    }
    if (!EC_GROUP_get_cofactor(grp->group, cofactor, bnctx)) {
        sae_debug(SAE_DEBUG_ERR, "unable to get cofactor for curve!\n");
        goto fail;
    }
    if (BN_cmp(cofactor, BN_value_one())) {
        /*
         * no curves with a co-factor > 1 are allowed. Technically they will work
         * but the special handling of them to deal with a small sub-group attack
         * when compared to how many of them are in this IANA registry (as of writing
         * this that number is zero) makes it better to just not support them.
         */
        sae_debug(SAE_DEBUG_ERR, "attempting to use a curve with a co-factor > 1!\n");
        goto fail;
    }
    grp->group_num = num;
    strncpy(grp->password, password, sizeof(grp->password));

    if (0) {
fail:
        BN_free(grp->order);
        BN_free(grp->prime);
        ret = -1;
    }
    BN_free(cofactor);

    return ret;
}

int
sae_parse_config (char *confdir, struct sae_config* config)
{
    int i;
    FILE *fp;
    char buf[80], *ptr;
    int ret;

    if (config == NULL)
        return -1;

    memset(config, 0, sizeof(*config));
    snprintf(conffile, sizeof(conffile), "%s/sae.conf", confdir);
    if ((fp = fopen(conffile, "r")) == NULL) {
        sae_debug(SAE_DEBUG_ERR, "cannot open configuration file, %s!\n", conffile);
        return -1;
    }
    while (!feof(fp)) {
        if (fgets(buf, sizeof(buf), fp) == 0) {
            continue;
        }
        if ((ret = parse_buffer(buf, &ptr)) < 0) {
            break;
        }
        if (ret == 0) {
            continue;
        }
        if (strncmp(buf, "group", strlen("group")) == 0) {
            i = 0;
            do {
                config->group[i++] = atoi(ptr);
                ptr = strstr(ptr, " ");
                if (ptr == NULL)
                    break;
                if (*ptr != '\n')
                    ptr++;
            } while (*ptr != '\n');
            config->num_groups = i;
        } else if (strncmp(buf, "password", strlen("password")) == 0) {
            strcpy(config->pwd, ptr);
        } else if (strncmp(buf, "debug", strlen("debug")) == 0) {
            config->debug = atoi(ptr);
        } else if (strncmp(buf, "retrans", strlen("retrans")) == 0) {
            config->retrans = atoi(ptr);
        } else if (strncmp(buf, "lifetime", strlen("lifetime")) == 0) {
            config->pmk_expiry = atoi(ptr);
        } else if (strncmp(buf, "thresh", strlen("thresh")) == 0) {
            config->open_threshold = atoi(ptr);
        } else if (strncmp(buf, "blacklist", strlen("blacklist")) == 0) {
            config->blacklist_timeout = atoi(ptr);
        } else if (strncmp(buf, "giveup", strlen("giveup")) == 0) {
            config->giveup_threshold = atoi(ptr);
        }
    }
    fclose(fp);
    return 0;
}

int
sae_parse_libconfig (struct config_setting_t *sae_section, struct sae_config* config)
{
    struct config_setting_t *setting, *group;
    char *pwd;

    memset(config, 0, sizeof(struct sae_config));
    config_setting_lookup_int(sae_section, "debug", (config_int_t *)&config->debug);
    setting = config_setting_get_member(sae_section, "group");
    if (setting != NULL) {
        while (1) {
            group = config_setting_get_elem(setting, config->num_groups);
            if (!group)
                break;
            config->group[config->num_groups] =
                config_setting_get_int_elem(setting, config->num_groups);
            config->num_groups++;
            if (config->num_groups == SAE_MAX_EC_GROUPS)
                break;
        }
    }
    if (config_setting_lookup_string(sae_section, "password", (const char **)&pwd)) {
        strncpy(config->pwd, pwd, SAE_MAX_PASSWORD_LEN);
        if (config->pwd[SAE_MAX_PASSWORD_LEN - 1] != 0) {
            fprintf(stderr, "WARNING: Truncating password\n");
            config->pwd[SAE_MAX_PASSWORD_LEN - 1] = 0;
        }
    }
    config_setting_lookup_int(sae_section, "retrans", (config_int_t *)&config->retrans);
    config_setting_lookup_int(sae_section, "lifetime", (config_int_t *)&config->pmk_expiry);
    config_setting_lookup_int(sae_section, "thresh", (config_int_t *)&config->open_threshold);
    config_setting_lookup_int(sae_section, "blacklist", (config_int_t *)&config->blacklist_timeout);
    config_setting_lookup_int(sae_section, "giveup", (config_int_t *)&config->giveup_threshold);
    return 0;
}

void
sae_dump_db (int unused)
{
    struct candidate *peer;

    fprintf(stderr, "SAE:\n");
    TAILQ_FOREACH(peer, &peers, entry) {
        fprintf(stderr, "\t" MACSTR " in state %s\n", MAC2STR(peer->peer_mac), state_to_string(peer->state));
    }
}

int
sae_initialize (char *ourssid, struct sae_config *config)
{
    GD *curr, *prev = NULL;
    int i;

    /* TODO: detect duplicate calls.  validate config. */

    EVP_add_digest(EVP_sha256());
    if ((out = BIO_new(BIO_s_file())) == NULL) {
        fprintf(stderr, "SAE: unable to create file BIO!\n");
        return -1;
    }
    BIO_set_fp(out, stderr, BIO_NOCLOSE);

    /*
     * initialize globals
     */
    memset(allzero, 0, SHA256_DIGEST_LENGTH);
#if 0
JC: Commented out until we decide whether this is needed (in which case we must
    be prepared to accept a binary, non-null terminated mesh ID) or not (the
    mesh_ssid is not used anywhere in this module, so maybe it can be dumped).

    memcpy(mesh_ssid, ourssid, strlen(ourssid));
#endif
    TAILQ_INIT(&peers);
    TAILQ_INIT(&blacklist);
    RAND_pseudo_bytes((unsigned char *)&token_generator, sizeof(unsigned long));
    if ((bnctx = BN_CTX_new()) == NULL) {
        fprintf(stderr, "cannot create bignum context!\n");
        return -1;
    }
    /*
     * set defaults and read in config
     */
    sae_debug_mask = config->debug;
    curr_open = 0;
    open_threshold = config->open_threshold ? config->open_threshold : 5;
    blacklist_timeout = config->blacklist_timeout ? config->blacklist_timeout
        : 30;
    giveup_threshold = config->giveup_threshold ? config->giveup_threshold :
        5;
    retrans = config->retrans ? config->retrans : 3;
    pmk_expiry = config->pmk_expiry ? config->pmk_expiry : 86400; /* one day */
    /*
     * create groups from configuration data
     */
    for (i=0; i<config->num_groups; i++) {
        if ((curr = (GD *)malloc(sizeof(GD))) == NULL) {
            sae_debug(SAE_DEBUG_ERR, "cannot malloc group definition!\n");
            return -1;
        }
        if (compute_group_definition(curr, config->pwd, config->group[i])) {
            free(curr);
            continue;
        }
        if (prev)
            prev->next = curr;
        else
            gd = curr;
        prev = curr;
        curr->next = NULL;
        sae_debug(SAE_DEBUG_STATE_MACHINE, "group %d is configured, prime is %d"
                " bytes\n", curr->group_num, BN_num_bytes(curr->prime));
    }
    return 1;
}

