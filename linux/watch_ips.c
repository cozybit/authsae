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
#include "watch_ips.h"

#include <assert.h>
#include <errno.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <pthread.h>
#include <stdbool.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "common.h"
#include "rekey.h"

static struct mesh_node *cfg = NULL;
static volatile bool run = true;
static int sock = -1;

/*
 * helpers
 */

static bool open_socket(int af) {
  if (sock != -1) {
    return true;
  }

  sock = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
  if (sock == -1) {
    sae_debug(SAE_DEBUG_ERR, "rekey: error creating the netlink socket for the address monitoring thread: %s\n",
        strerror(errno));
    return false;
  }

  struct sockaddr_nl addr;
  memset(&addr, 0, sizeof(addr));
  addr.nl_family = AF_NETLINK;
  addr.nl_groups = (af == AF_INET) ? RTMGRP_IPV4_IFADDR : RTMGRP_IPV6_IFADDR;

  bool r = !bind(sock, (struct sockaddr *) &addr, sizeof(addr));
  if (!r) {
    sae_debug(SAE_DEBUG_ERR, "rekey: error binding the netlink socket for the address monitoring thread: %s\n",
        strerror(errno));
    close(sock);
    sock = -1;
  }

  return r;
}

static void close_socket(void) {
  if (sock == -1) {
    return;
  }

  shutdown(sock, SHUT_WR);
  close(sock);
  sock = -1;
}

/*
 * thread
 */

static void *monitor_interface_addresses(void *arg) {
  static char buffer[4096];

  ssize_t len = 0;

  while (run) {
    while ((len = recv(sock, buffer, sizeof(buffer), 0)) > 0) {
      if (!run) {
        goto out;
      }

      int idx = !cfg ? 0 : if_nametoindex(cfg->conf->bridge[0] ? cfg->conf->bridge : cfg->conf->interface);
      bool changed = false;

      struct nlmsghdr *nlh = (struct nlmsghdr *) buffer;
      while (!changed && NLMSG_OK(nlh, len) && (nlh->nlmsg_type != NLMSG_DONE)) {
        if ((nlh->nlmsg_type == RTM_NEWADDR) || (nlh->nlmsg_type == RTM_DELADDR)) {
          struct ifaddrmsg *ifa = (struct ifaddrmsg *) NLMSG_DATA(nlh);
          struct rtattr *rth = IFA_RTA(ifa);
          int rtl = IFA_PAYLOAD(nlh);

          while (!changed && rtl && RTA_OK(rth, rtl)) {
            if ((rth->rta_type == IFA_LOCAL) && (!cfg || (ifa->ifa_family == cfg->conf->rekey_multicast_group_family))
                && (!idx || (idx == ifa->ifa_index))) {
              char name[IF_NAMESIZE];
              sae_debug(SAE_DEBUG_REKEY, "rekey: an IP address changed on interface '%s'\n",
                  if_indextoname(ifa->ifa_index, name));
              changed = true;
            }
            rth = RTA_NEXT(rth, rtl);
          }
        }
        nlh = NLMSG_NEXT(nlh, len);
      }

      if (!run) {
        goto out;
      }

      if (changed) {
        rekey_reopen_sockets();
      }
    }

    if (!run) {
      goto out;
    }

    if (len == -1) {
      sae_debug(SAE_DEBUG_ERR, "rekey: read error in the address monitoring thread: %s\n", strerror(errno));
    }
  }

  out: return NULL;
}

/*
 * lifecycle
 */

static pthread_t thread = 0;

void watch_ips_init(struct mesh_node *config) {
  if (thread) {
    return;
  }

  assert(config);

  cfg = config;
  run = true;

  if (!open_socket(cfg->conf->rekey_multicast_group_family)) {
    goto err;
  }

  if (pthread_create(&thread, NULL, monitor_interface_addresses, NULL)) {
    sae_debug(SAE_DEBUG_ERR, "rekey: error creating the address monitoring thread: %s\n", strerror(errno));
    goto err;
  }

  return;

  err: thread = 0;
  close_socket();
  run = false;
  cfg = NULL;
}

void watch_ips_close() {
  if (!thread) {
    return;
  }

  run = false;
  (void) pthread_cancel(thread);

  (void) pthread_join(thread, NULL);
  thread = 0;

  close_socket();

  cfg = NULL;
}
