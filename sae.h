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

#ifndef _SAE_H_
#define _SAE_H_
#include <libconfig.h>
#include "ieee802_11.h"

#define    SAE_MAX_EC_GROUPS    10
#define    SAE_MAX_PASSWORD_LEN 80

struct sae_config {
    int group[SAE_MAX_EC_GROUPS];
    int num_groups;
    char pwd[SAE_MAX_PASSWORD_LEN];
    int debug;
    int retrans;
    int pmk_expiry;
    int open_threshold;
    int blacklist_timeout;
    int giveup_threshold;
};

/* You may choose not to call sae_parse_config and
 * populate sae_config in some other way before
 * invoking sae_initialize() */
int sae_parse_config(char* confdir, struct sae_config *config);
int sae_parse_libconfig (struct config_setting_t *sae_section, struct sae_config* config);
int sae_initialize(char *ssid, struct sae_config *config);
int process_mgmt_frame(struct ieee80211_mgmt_frame *frame, int len,
                       unsigned char *local_mac_addr, void *cookie);
void sae_read_config(int signal);
void sae_dump_db (int signal);
int prf (unsigned char *key, int keylen, unsigned char *label, int labellen,
     unsigned char *context, int contextlen,
     unsigned char *result, int resultbitlen);

#endif  /* _SAE_H_ */
