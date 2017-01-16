/*
 * Copyright (c) CoCo Communications, 2015
 * Copyright (c) Pelagic, 2016
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

#include <errno.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <pthread.h>
#include <stdbool.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "common.h"
#include "rekey.h"

static struct mesh_node *cfg = NULL;

static pthread_t thread = 0;
static volatile bool run = true;
static char buffer[4096];
static int sock = -1;

static bool open_socket(void) {
  if (sock != -1) {
    return true;
  }

  sock = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
  if (sock == -1) {
    return false;
  }

  struct sockaddr_nl addr;
  memset(&addr, 0, sizeof(addr));
  addr.nl_family = AF_NETLINK;
  addr.nl_groups = RTMGRP_IPV4_IFADDR; // TODO for IPv6 add RTMGRP_IPV6_IFADDR

  bool r = !bind(sock, (struct sockaddr *) &addr, sizeof(addr));
  if (!r) {
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

static int get_interface_index(void) {
  int index = 0;

  char *ifname;
  size_t len;
  if (cfg->conf->rekey_interface_is_bridge) {
    ifname = cfg->conf->bridge;
    len = sizeof(cfg->conf->bridge);
  } else {
    ifname = cfg->conf->interface;
    len = sizeof(cfg->conf->interface);
  }

  struct if_nameindex * ifaces = if_nameindex();
  if (ifaces) {
    bool loop = true;
    struct if_nameindex *iface;
    for (iface = ifaces; loop && (iface->if_index || iface->if_name); iface++) {
      if (iface->if_name && !strncmp(ifname, iface->if_name, len)) {
        index = iface->if_index;
        loop = false;
      }
    }

    if_freenameindex(ifaces);
  }

  return index;
}

static void* monitor_interface_addresses(void *info) {
  ssize_t len = 0;

  while (run && ((len = recv(sock, buffer, sizeof(buffer), 0)) > 0)) {
    bool changed = false;

    int idx = get_interface_index();

    struct nlmsghdr *nlh = (struct nlmsghdr *) buffer;
    while (NLMSG_OK(nlh, len) && (nlh->nlmsg_type != NLMSG_DONE) && !changed) {
      if ((nlh->nlmsg_type == RTM_NEWADDR) || (nlh->nlmsg_type == RTM_DELADDR)) {
        struct ifaddrmsg *ifa = (struct ifaddrmsg *) NLMSG_DATA(nlh);
        struct rtattr *rth = IFA_RTA(ifa);
        int rtl = IFA_PAYLOAD(nlh);

        while (rtl && RTA_OK(rth, rtl) && !changed) {
          if ((rth->rta_type == IFA_LOCAL) && (ifa->ifa_family == cfg->conf->rekey_multicast_group_family)
              && (!idx || (idx == ifa->ifa_index))) {
            sae_debug(SAE_DEBUG_PROTOCOL_MSG, "rekey: an IP address changed on interface with index %d\n",
                ifa->ifa_index);
            changed = true;
          }
          rth = RTA_NEXT(rth, rtl);
        }
      }
      nlh = NLMSG_NEXT(nlh, len);
    }

    if (run && changed) {
      rekey_reopen_sockets();
    }
  }

  if (len == -1) {
    sae_debug(SAE_DEBUG_ERR, "rekey: read error in monitor_addresses thread: %s\n", strerror(errno));
  }

  close_socket();

  return NULL;
}

void watch_ips_init(struct mesh_node *config) {
  if (thread) {
    return;
  }

  cfg = config;

  run = true;
  memset(buffer, 0, sizeof(buffer));

  if (!open_socket()) {
    goto err;
  }

  int ok = pthread_create(&thread, NULL, monitor_interface_addresses, NULL);
  if (!ok) {
    return;
  }

  sae_debug(SAE_DEBUG_ERR, "rekey: creating the monitor_addresses thread failed (%d)\n", ok);

  err: close_socket();
  thread = 0;
}

void watch_ips_close() {
  if (!thread) {
    return;
  }

  run = false;
  (void) pthread_cancel(thread);
  /* close_socket() is called by the thread */
  thread = 0;

  cfg = NULL;
}
