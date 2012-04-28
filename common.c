/*
 * Copyright (c) Dan Harkins, 2008, 2009, 2010
 * Copyright (c) cozybit Inc., 2011
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
//#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include <stdio.h>
#include "common.h"
#include "ieee802_11.h"

unsigned int sae_debug_mask;

/*
 * parser_buffer()
 *      given an attribute/value pair in the form of attr=value
 *      return a pointer to the value
 */
int
parse_buffer (char *buf, char **val)
{
    char *ptr;

    *val = NULL;
    if (buf[0] == '#') {
        return 0;
    }
    ptr = buf;
    while (*ptr != '\n') {
        ptr++;
    }
    if (ptr == buf) {
        return 0;
    }
    *ptr = '\0';
    ptr = strstr(buf, "=");
    if (ptr == NULL) {
        return -1;
    }
    *ptr = '\0';
    do {
        ptr++;
    } while (*ptr == ' ');
    *val = ptr;

    return 1;
}

void sae_debug (int level, const char *fmt, ...)
{
    va_list argptr;

    if (sae_debug_mask & level) {
        va_start(argptr, fmt);
        vfprintf(stderr, fmt, argptr);
        va_end(argptr);
    }
}

void sae_hexdump(int level, const char *label, const unsigned char *start, int len)
{
    const unsigned char *pos;
    int i;

    if (sae_debug_mask & level) {
        fprintf(stderr, "----------\n");
        fprintf(stderr, "%s hexdump", label);
        pos = start;
        for (i=0; i<len; i++) {
            if (!(i%20)) fprintf(stderr, "\n");
            fprintf(stderr, "%02x ", (unsigned char) *pos++);
        }
        fprintf(stderr, "\n----------\n\n");
        fflush(stdout);
    }
    return;
}


void parse_ies(unsigned char *start, int len, struct info_elems *elems)
{
    int left = len;
    unsigned char *pos = start;

    memset(elems, 0, sizeof(*elems));

    while (left >= 2) {
        unsigned char id, elen;

        id = *pos++;
        elen = *pos++;
        left -= 2;

        //fprintf(stderr, "parse_ies id=%d elen=%d\n", id, elen);

        if (elen > left)
            break;

        switch (id) {
            case IEEE80211_EID_SUPPORTED_RATES:
                elems->sup_rates = pos;
                elems->sup_rates_len = elen;
                break;
            case IEEE80211_EID_EXTENDED_SUP_RATES:
                elems->ext_rates = pos;
                elems->ext_rates_len = elen;
                break;
            case IEEE80211_EID_RSN:
                elems->rsn = pos;
                elems->rsn_len = elen;
                break;
	    case IEEE80211_EID_HT_CAPABILITY:
		elems->ht_cap = pos;
		elems->ht_cap_len = elen;
		break;
	    case IEEE80211_EID_HT_OPERATION:
		elems->ht_info = pos;
		elems->ht_info_len = elen;
		break;
            case IEEE80211_EID_MESH_ID:
                elems->mesh_id = pos;
                elems->mesh_id_len = elen;
                break;
            case IEEE80211_EID_MESH_PEERING:
                elems->mesh_peering = pos;
                elems->mesh_peering_len = elen;
                break;
            case IEEE80211_EID_MESH_CONFIG:
                elems->mesh_config = pos;
                elems->mesh_config_len = elen;
                break;
            case IEEE80211_EID_AMPE:
                elems->ampe = (struct ampe_ie *) pos;
                elems->ampe_len = elen;
		break;
            case IEEE80211_EID_MIC:
                elems->mic = pos;
                elems->mic_len = elen;
                /*  After the MIC there IEs there's the AMPE encrypted IE.  Stop here */
                return;
            default:
                break;
        }
        left -= elen;
        pos += elen;
    }
}
