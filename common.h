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

#ifndef _COMMON_H_
#define _COMMON_H_
#include <string.h>

#define MESHD_STA       0
#define MESHD_ADHOC     1
#define MESHD_HOSTAP    2
#define MESHD_MONITOR   3
#define MESHD_IBSS      4
#define MESHD_11a       1
#define MESHD_11b       2
#define MESHD_11g       3
#define MESHD_MAX_SSID_LEN 32
int parse_buffer(char *, char **);

#define SAE_DEBUG_ERR           0x01
#define SAE_DEBUG_PROTOCOL_MSG  0x02
#define SAE_DEBUG_STATE_MACHINE 0x04
#define SAE_DEBUG_CRYPTO        0x08
#define SAE_DEBUG_CRYPTO_VERB   0x10
#define AMPE_DEBUG_CANDIDATES   0x20
#define MESHD_DEBUG             0x40
#define AMPE_DEBUG_FSM          0x80
#define AMPE_DEBUG_KEYS        0x100
#define AMPE_DEBUG_ERR         0x200
extern unsigned int sae_debug_mask;
void sae_debug (int level, const char *fmt, ...);
void sae_hexdump(int level, const char *label, const unsigned char *start, int
        len);

#ifndef u8
#define u8 unsigned char
#endif
#ifndef le16
#define le16 unsigned short
#endif
#ifndef u16
#define u16 unsigned short
#endif
#ifndef le32
#define le32 unsigned int
#endif
#ifndef LIBCONFIG_SETTING_INT_AS_LONG
typedef int config_int_t;
#else
typedef long int config_int_t;
#endif
#endif  /* _COMMON_H_ */
