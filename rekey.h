/*
 * Copyright (c) CoCo Communications, 2015
 * Copyright (c) Pelagic, 2017
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
 *         Jesse Jones (jjones at cococorp dot com)"
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

#ifndef _SAE_REKEY_H_
#define _SAE_REKEY_H_

#include <netinet/in.h>

#include "ampe.h"
#include "peers.h"
#include "service.h"

#define REKEY_ENABLE_DEF                   (false)
#define REKEY_MULTICAST_GROUP_FAMILY_DEF   (AF_INET)
#define REKEY_MULTICAST_GROUP_ADDRESS_DEF  (htonl(0xE00000C8)) /* 224.0.0.200 */
#define REKEY_PING_PORT_DEF                (4875)
#define REKEY_PONG_PORT_DEF                (4876)
#define REKEY_PING_COUNT_MAX_DEF           (32)
#define REKEY_PING_TIMEOUT_MSECS_DEF       (500)
#define REKEY_PING_JITTER_MSECS_DEF        (100)
#define REKEY_REAUTH_COUNT_MAX_DEF         (8)
#define REKEY_OK_PING_COUNT_MAX_DEF        (16)

void rekey_init(service_context srvctx, struct mesh_node *mesh);
void rekey_close(void);

void rekey_verify_peer(struct candidate *peer);
void rekey_reopen_sockets(void);

#endif  /* _SAE_REKEY_H_ */
