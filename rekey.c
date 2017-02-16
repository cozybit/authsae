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

#include "rekey.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/ip.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "common.h"
#include "ieee802_11.h"
#include "sae.h"

#define PACKET_TYPE_PING    (0x01)
#define PACKET_TYPE_PONG    (0x02)

#define PACKET_VERSION_PING (0x01)
#define PACKET_VERSION_PONG (0x01)

typedef struct {
  uint8_t type;
  uint8_t version;
}__attribute__((packed)) packet_header;

typedef struct {
  packet_header header;
  uint8_t dst_mac[ETH_ALEN];
  uint8_t src_mac[ETH_ALEN];
  in_port_t src_port;
}__attribute__((packed)) packet_ping;

typedef struct {
  packet_header header;
  uint8_t dst_mac[ETH_ALEN];
  uint8_t src_mac[ETH_ALEN];
}__attribute__((packed)) packet_pong;

typedef union {
  packet_ping ping;
  packet_pong pong;
}__attribute__((packed)) packet_struct;

static service_context ctx = NULL;
static struct mesh_node *cfg = NULL;

#define IPPROTO(af)   ((af == AF_INET) ? IPPROTO_IP : IPPROTO_IPV6)
#define IPMCLOOP(af)  ((af == AF_INET) ? IP_MULTICAST_LOOP : IPV6_MULTICAST_LOOP)
#define IPMCTTL(af)   ((af == AF_INET) ? IP_MULTICAST_TTL : IPV6_MULTICAST_HOPS)
#define IPMCJOIN(af)  ((af == AF_INET) ? IP_ADD_MEMBERSHIP : IPV6_ADD_MEMBERSHIP)
#define IPMCLEAVE(af) ((af == AF_INET) ? IP_DROP_MEMBERSHIP : IPV6_DROP_MEMBERSHIP)

/*
 * helpers
 */

static void *get_socket_address_ip(struct sockaddr_storage *sa) {
  if (sa->ss_family == AF_INET) {
    return &(((struct sockaddr_in*) sa)->sin_addr);
  }

  return &(((struct sockaddr_in6*) sa)->sin6_addr);
}

static bool bind_socket_to_interface(int sock, const char* iface) {
  if (!iface) {
    return false;
  }

  struct ifreq ifr;
  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, iface, sizeof(ifr.ifr_name));
  ifr.ifr_name[sizeof(ifr.ifr_name) - 1] = '\0';

  return !setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, (void *) &ifr, sizeof(ifr));
}

static bool bind_socket_to_ip_and_port(int sock, int af, ip_address *ip, in_port_t port) {
  struct sockaddr_storage addr;
  memset(&addr, 0, sizeof(addr));
  addr.ss_family = af;

  if (af == AF_INET) {
    struct sockaddr_in *addr4 = (struct sockaddr_in *) &addr;
    addr4->sin_addr = ip->v4;
    addr4->sin_port = port;
  } else {
    struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *) &addr;
    addr6->sin6_addr = ip->v6;
    addr6->sin6_port = port;
  }

  return !bind(sock, (struct sockaddr *) &addr, sizeof(addr));
}

static int create_dgram_socket(int af) {
  int sock = socket(af, SOCK_DGRAM, 0);
  if (sock == -1) {
    return -1;
  }

  int reuse = 1;
  if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse))) {
    close(sock);
    return -1;
  }

  return sock;
}

/*
 * pong send & receive
 */

static int pong_socket = -1;

static void pong_tx(struct candidate *peer, struct sockaddr_storage *src, in_port_t port) {
  if (!peer || !src || !port || (pong_socket == -1)) {
    return;
  }

  packet_struct packet;
  packet.pong.header.type = PACKET_TYPE_PONG;
  packet.pong.header.version = PACKET_VERSION_PONG;
  memcpy(packet.pong.dst_mac, peer->peer_mac, sizeof(packet.pong.dst_mac));
  memcpy(packet.pong.src_mac, peer->my_mac, sizeof(packet.pong.src_mac));

  struct sockaddr_storage dst;
  memset(&dst, 0, sizeof(dst));
  dst.ss_family = src->ss_family;
  if (dst.ss_family == AF_INET) {
    struct sockaddr_in *src4 = (struct sockaddr_in *) src;
    struct sockaddr_in *dst4 = (struct sockaddr_in *) &dst;
    dst4->sin_addr = src4->sin_addr;
    dst4->sin_port = port;
  } else {
    struct sockaddr_in6 *src6 = (struct sockaddr_in6 *) src;
    struct sockaddr_in6 *dst6 = (struct sockaddr_in6 *) &dst;
    dst6->sin6_addr = src6->sin6_addr;
    dst6->sin6_port = port;
  }

  char str[INET6_ADDRSTRLEN];
  sae_debug(SAE_DEBUG_REKEY, "rekey: pong to   " MACSTR " (%s)\n", MAC2STR(peer->peer_mac),
      inet_ntop(dst.ss_family, get_socket_address_ip(&dst), str, sizeof(str)));

  int bytes = sendto(pong_socket, &packet.pong, sizeof(packet.pong), 0, (struct sockaddr *) &dst, sizeof(dst));

  if (bytes == sizeof(packet.pong)) {
    return;
  }

  if (bytes == -1) {
    sae_debug(SAE_DEBUG_ERR, "rekey: pong to   " MACSTR " (%s) failed: %s\n", MAC2STR(peer->peer_mac),
        inet_ntop(dst.ss_family, get_socket_address_ip(&dst), str, sizeof(str)), strerror(errno));
    return;
  }

  sae_debug(SAE_DEBUG_REKEY, "rekey: pong to   " MACSTR " (%s) sent %d bytes instead of %d\n", MAC2STR(peer->peer_mac),
      bytes, inet_ntop(dst.ss_family, get_socket_address_ip(&dst), str, sizeof(str)), sizeof(packet.pong));
}

static void pong_rx(int sock, void *data) {
  char str[INET6_ADDRSTRLEN];
  uint8_t buffer[sizeof(packet_struct) + 1];
  packet_struct *packet = (packet_struct *) buffer;
  struct sockaddr_storage src;
  socklen_t src_len = sizeof(src);

  int bytes = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *) &src, &src_len);

  if (bytes == sizeof(packet->pong)) {
    if (packet->pong.header.type != PACKET_TYPE_PONG) {
      sae_debug(SAE_DEBUG_REKEY, "rekey: pong from %s sent type %u instead of %u, ignored\n",
          inet_ntop(src.ss_family, get_socket_address_ip(&src), str, sizeof(str)), packet->pong.header.type,
          PACKET_TYPE_PONG);
      return;
    }

    if (packet->pong.header.version != PACKET_VERSION_PONG) {
      sae_debug(SAE_DEBUG_REKEY, "rekey: pong from %s sent version %u instead of %u, ignored\n",
          inet_ntop(src.ss_family, get_socket_address_ip(&src), str, sizeof(str)), packet->pong.header.version,
          PACKET_VERSION_PONG);
      return;
    }

    struct candidate *peer = find_peer(packet->pong.src_mac, 1);
    if (!peer) {
      sae_debug(SAE_DEBUG_REKEY, "rekey: pong from %s sent unknown accepted peer " MACSTR ", ignored\n",
          inet_ntop(src.ss_family, get_socket_address_ip(&src), str, sizeof(str)), MAC2STR(packet->pong.src_mac));
      return;
    }

    if (memcmp(packet->pong.dst_mac, peer->my_mac, sizeof(packet->pong.dst_mac))) {
      sae_debug(SAE_DEBUG_REKEY,
          "rekey: pong from " MACSTR " (%s) sent 'me' " MACSTR " instead of " MACSTR ", ignored\n",
          MAC2STR(packet->pong.src_mac), inet_ntop(src.ss_family, get_socket_address_ip(&src), str, sizeof(str)),
          MAC2STR(packet->pong.dst_mac), MAC2STR(peer->my_mac));
      return;
    }

    /* keys are installed correctly */

    sae_debug(SAE_DEBUG_REKEY, "rekey: pong from " MACSTR " (%s): keys are installed correctly\n",
        MAC2STR(packet->pong.src_mac), inet_ntop(src.ss_family, get_socket_address_ip(&src), str, sizeof(str)));

    srv_rem_timeout(ctx, peer->rekey_ping_timer);
    peer->rekey_ping_timer = 0;
    peer->rekey_ping_count = 0;
    peer->rekey_reauth_count = 0;
    peer->rekey_ok = 1;
    peer->rekey_ok_ping_rx = 0;
    return;
  }

  if (bytes == -1) {
    sae_debug(SAE_DEBUG_ERR, "rekey: pong rx failed: %s\n", strerror(errno));
    return;
  }

  sae_debug(SAE_DEBUG_REKEY, "rekey: pong from %s sent %d bytes instead of %d\n",
      inet_ntop(src.ss_family, get_socket_address_ip(&src), str, sizeof(str)), bytes, sizeof(packet->pong));
}

static void pong_socket_close(void) {
  if (pong_socket == -1) {
    return;
  }

  srv_rem_input(ctx, pong_socket);

  close(pong_socket);
  pong_socket = -1;
}

static void pong_socket_create(const char* iface, int af) {
  if (pong_socket != -1) {
    return;
  }

  pong_socket = create_dgram_socket(af);
  if (pong_socket == -1) {
    goto err;
  }

  if (!bind_socket_to_interface(pong_socket, iface)) {
    goto err;
  }

  ip_address bind_ip;
  memset(&bind_ip, 0, sizeof(bind_ip));
  if (af == AF_INET) {
    bind_ip.v4.s_addr = htonl(INADDR_ANY);
  } else {
    bind_ip.v6 = in6addr_any;
  }

  if (!bind_socket_to_ip_and_port(pong_socket, af, &bind_ip, cfg->conf->rekey_pong_port)) {
    goto err;
  }

  if (fcntl(pong_socket, F_SETFL, O_NDELAY)) {
    goto err;
  }

  if (srv_add_input(ctx, pong_socket, NULL, pong_rx)) {
    goto err;
  }

  return;

  err: pong_socket_close();
}

/*
 * ping receive
 */

static int ping_socket_rx_af = AF_INET;
static int ping_socket_rx_ifindex = 0;
static int ping_socket_rx = -1;

static void ping_rx(int sock, void *data) {
  char str[INET6_ADDRSTRLEN];
  uint8_t buffer[sizeof(packet_struct) + 1];
  packet_struct *packet = (packet_struct *) buffer;
  struct sockaddr_storage src;
  socklen_t src_len = sizeof(src);

  int bytes = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *) &src, &src_len);

  if (bytes == sizeof(packet->ping)) {
    if (packet->ping.header.type != PACKET_TYPE_PING) {
      sae_debug(SAE_DEBUG_REKEY, "rekey: ping from %s sent type %u instead of %u, ignored\n",
          inet_ntop(src.ss_family, get_socket_address_ip(&src), str, sizeof(str)), packet->ping.header.type,
          PACKET_TYPE_PING);
      return;
    }

    if (packet->ping.header.version != PACKET_VERSION_PING) {
      sae_debug(SAE_DEBUG_REKEY, "rekey: ping from %s sent version %u instead of %u, ignored\n",
          inet_ntop(src.ss_family, get_socket_address_ip(&src), str, sizeof(str)), packet->ping.header.version,
          PACKET_VERSION_PING);
      return;
    }

    struct candidate *peer = find_peer(packet->ping.src_mac, 1);
    if (!peer) {
      sae_debug(SAE_DEBUG_REKEY, "rekey: ping from %s sent unknown accepted peer " MACSTR ", ignored\n",
          inet_ntop(src.ss_family, get_socket_address_ip(&src), str, sizeof(str)), MAC2STR(packet->ping.src_mac));
      return;
    }

    if (memcmp(packet->ping.dst_mac, peer->my_mac, sizeof(packet->ping.dst_mac))) {
      /* not meant for me */
      return;
    }

    sae_debug(SAE_DEBUG_REKEY, "rekey: ping from " MACSTR " (%s)\n", MAC2STR(packet->ping.src_mac),
        inet_ntop(src.ss_family, get_socket_address_ip(&src), str, sizeof(str)));

    /* re-authenticate when we concluded that keys are installed correctly but we are still receiving pings */
    if (peer->rekey_ok) {
      peer->rekey_ok_ping_rx++;
      if (peer->rekey_ok_ping_rx > cfg->conf->rekey_ok_ping_count_max) {
        sae_debug(SAE_DEBUG_REKEY,
            "rekey: too many pings (%u) from " MACSTR " (%s) while considering keys correctly installed,"
            " doing reauthentication\n", peer->rekey_ok_ping_rx, MAC2STR(packet->ping.src_mac),
            inet_ntop(src.ss_family, get_socket_address_ip(&src), str, sizeof(str)));
        peer->rekey_ok_ping_rx = 0;
        do_reauth(peer);
        return;
      }
    }

    pong_tx(peer, &src, packet->ping.src_port);
    return;
  }

  if (bytes == -1) {
    sae_debug(SAE_DEBUG_ERR, "rekey: ping rx failed: %s\n", strerror(errno));
    return;
  }

  sae_debug(SAE_DEBUG_REKEY, "rekey: ping from %s sent %d bytes instead of %d\n",
      inet_ntop(src.ss_family, get_socket_address_ip(&src), str, sizeof(str)), bytes, sizeof(packet->ping));
}

static void ping_socket_close_rx(void) {
  if (ping_socket_rx == -1) {
    return;
  }

  srv_rem_input(ctx, ping_socket_rx);

  if (ping_socket_rx_ifindex) {
    if (ping_socket_rx_af == AF_INET) {
      struct ip_mreq mreq;
      memset(&mreq, 0, sizeof(mreq));
      mreq.imr_multiaddr.s_addr = cfg->conf->rekey_multicast_group_address.v4.s_addr;
      mreq.imr_interface.s_addr = htonl(INADDR_ANY);
      (void) setsockopt(ping_socket_rx, IPPROTO(ping_socket_rx_af), IPMCLEAVE(ping_socket_rx_af), &mreq, sizeof(mreq));
    } else {
      struct ipv6_mreq mreq;
      memset(&mreq, 0, sizeof(mreq));
      mreq.ipv6mr_multiaddr = cfg->conf->rekey_multicast_group_address.v6;
      mreq.ipv6mr_interface = ping_socket_rx_ifindex;
      (void) setsockopt(ping_socket_rx, IPPROTO(ping_socket_rx_af), IPMCLEAVE(ping_socket_rx_af), &mreq, sizeof(mreq));
    }
  }

  close(ping_socket_rx);
  ping_socket_rx = -1;
  ping_socket_rx_ifindex = 0;
}

static void ping_socket_create_rx(const char* iface, int af) {
  if (ping_socket_rx != -1) {
    return;
  }

  ping_socket_rx_af = af;

  ping_socket_rx_ifindex = if_nametoindex(iface);
  if (!ping_socket_rx_ifindex) {
    goto err;
  }

  ping_socket_rx = create_dgram_socket(af);
  if (ping_socket_rx == -1) {
    goto err;
  }

  if (!bind_socket_to_interface(ping_socket_rx, iface)) {
    goto err;
  }

  ip_address bind_ip;
  memset(&bind_ip, 0, sizeof(bind_ip));
  if (af == AF_INET) {
    bind_ip.v4.s_addr = htonl(INADDR_ANY);
  } else {
    bind_ip.v6 = in6addr_any;
  }

  if (!bind_socket_to_ip_and_port(ping_socket_rx, af, &bind_ip, cfg->conf->rekey_ping_port)) {
    goto err;
  }

  uint8_t loopback = 0;
  if (setsockopt(ping_socket_rx, IPPROTO(af), IPMCLOOP(af), &loopback, sizeof(loopback)) == -1) {
    goto err;
  }

  if (af == AF_INET) {
    struct ip_mreq mreq;
    memset(&mreq, 0, sizeof(mreq));
    mreq.imr_multiaddr = cfg->conf->rekey_multicast_group_address.v4;
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    if (setsockopt(ping_socket_rx, IPPROTO(af), IPMCJOIN(af), &mreq, sizeof(mreq)) == -1) {
      goto err;
    }
  } else {
    struct ipv6_mreq mreq;
    memset(&mreq, 0, sizeof(mreq));
    mreq.ipv6mr_multiaddr = cfg->conf->rekey_multicast_group_address.v6;
    mreq.ipv6mr_interface = ping_socket_rx_ifindex;
    if (setsockopt(ping_socket_rx, IPPROTO(af), IPMCJOIN(af), &mreq, sizeof(mreq)) == -1) {
      goto err;
    }
  }

  if (srv_add_input(ctx, ping_socket_rx, NULL, ping_rx)) {
    goto err;
  }

  return;

  err: ping_socket_close_rx();
}

/*
 * ping send
 */

static int ping_socket_tx = -1;

static void ping_tx(timerid id, void *data) {
  if (!data || !cfg) {
    return;
  }

  struct candidate *peer = (struct candidate *) data;

  peer->rekey_ping_count++;

  /* check whether we sent too many pings */
  if (peer->rekey_ping_count > cfg->conf->rekey_ping_count_max) {
    sae_debug(SAE_DEBUG_REKEY, "rekey: too many pings (%u) to " MACSTR "\n", peer->rekey_ping_count,
        MAC2STR(peer->peer_mac));

    srv_rem_timeout(ctx, peer->rekey_ping_timer);
    peer->rekey_ping_timer = 0;
    peer->rekey_ping_count = 0;

    /* check whether we can do another reauthentication */
    if (peer->rekey_reauth_count < cfg->conf->rekey_reauth_count_max) {
      rekey_reopen_sockets();
      peer->rekey_reauth_count++;
      sae_debug(SAE_DEBUG_REKEY, "rekey: reauthentication %u with " MACSTR "\n", peer->rekey_reauth_count,
          MAC2STR(peer->peer_mac));
      do_reauth(peer);
      return;
    }

    sae_debug(SAE_DEBUG_REKEY, "rekey: too many reauthentications (%u) with " MACSTR "\n", peer->rekey_reauth_count,
        MAC2STR(peer->peer_mac));

    return;
  }

  /* ping */

  packet_struct packet;
  memset(&packet, 0, sizeof(packet));
  packet.ping.header.type = PACKET_TYPE_PING;
  packet.ping.header.version = PACKET_VERSION_PING;
  memcpy(packet.ping.dst_mac, peer->peer_mac, sizeof(packet.ping.dst_mac));
  memcpy(packet.ping.src_mac, peer->my_mac, sizeof(packet.ping.src_mac));
  packet.ping.src_port = cfg->conf->rekey_pong_port;

  struct sockaddr_storage dst;
  memset(&dst, 0, sizeof(dst));
  dst.ss_family = cfg->conf->rekey_multicast_group_family;
  void * dst_addr;
  if (dst.ss_family == AF_INET) {
    struct sockaddr_in *dst4 = (struct sockaddr_in *) &dst;
    dst4->sin_addr = cfg->conf->rekey_multicast_group_address.v4;
    dst4->sin_port = cfg->conf->rekey_ping_port;
    dst_addr = &dst4->sin_addr;
  } else {
    struct sockaddr_in6 *dst6 = (struct sockaddr_in6 *) &dst;
    dst6->sin6_addr = cfg->conf->rekey_multicast_group_address.v6;
    dst6->sin6_port = cfg->conf->rekey_ping_port;
    dst_addr = &dst6->sin6_addr;
  }

  char str[INET6_ADDRSTRLEN];
  sae_debug(SAE_DEBUG_REKEY, "rekey: ping %u to " MACSTR " (%s)\n", peer->rekey_ping_count, MAC2STR(peer->peer_mac),
      inet_ntop(dst.ss_family, dst_addr, str, sizeof(str)));

  int bytes = sendto(ping_socket_tx, &packet.ping, sizeof(packet.ping), 0, (struct sockaddr *) &dst, sizeof(dst));

  if (bytes == sizeof(packet.ping)) {
    srv_rem_timeout(ctx, peer->rekey_ping_timer);
    peer->rekey_ping_timer = srv_add_timeout(ctx, SRV_MSEC(cfg->conf->rekey_ping_timeout), ping_tx, peer);
    if (!peer->rekey_ping_timer) {
      sae_debug(SAE_DEBUG_ERR, "rekey: ping %u to " MACSTR " failed to reschedule its ping timeout\n",
          peer->rekey_ping_count, MAC2STR(peer->peer_mac));
    }
    return;
  }

  if (bytes == -1) {
    sae_debug(SAE_DEBUG_ERR, "rekey: ping %u to " MACSTR " failed: %s\n", peer->rekey_ping_count,
        MAC2STR(peer->peer_mac), strerror(errno));
    return;
  }

  sae_debug(SAE_DEBUG_REKEY, "rekey: ping %u to " MACSTR " sent %d bytes instead of %d\n", peer->rekey_ping_count,
      MAC2STR(peer->peer_mac), bytes, sizeof(packet.ping));
}

static void ping_socket_close_tx(void) {
  if (ping_socket_tx == -1) {
    return;
  }

  close(ping_socket_tx);
  ping_socket_tx = -1;
}

static void ping_socket_create_tx(const char* iface, int af) {
  if (ping_socket_tx != -1) {
    return;
  }

  ping_socket_tx = create_dgram_socket(af);
  if (ping_socket_tx == -1) {
    goto err;
  }

  if (!bind_socket_to_interface(ping_socket_tx, iface)) {
    goto err;
  }

  uint8_t loopback = 0;
  if (setsockopt(ping_socket_tx, IPPROTO(af), IPMCLOOP(af), &loopback, sizeof(loopback)) == -1) {
    goto err;
  }

  int ttl = 1;
  if (setsockopt(ping_socket_tx, IPPROTO(af), IPMCTTL(af), &ttl, sizeof(ttl))) {
    goto err;
  }

  if (fcntl(ping_socket_tx, F_SETFL, O_NDELAY)) {
    goto err;
  }

  return;

  err: ping_socket_close_tx();
}

/*
 * sockets
 */

#define ALL_SOCKETS_OPEN ((ping_socket_tx != -1) && (ping_socket_rx != -1) && (pong_socket != -1))

static void rekey_sockets_close(void) {
  sae_debug(SAE_DEBUG_REKEY, "rekey: closing sockets\n");

  ping_socket_close_tx();
  ping_socket_close_rx();
  pong_socket_close();
}

static void rekey_sockets_reopen(void) {
  if (!cfg) {
    return;
  }

  sae_debug(SAE_DEBUG_REKEY, "rekey: reopening sockets\n");

  int af = cfg->conf->rekey_multicast_group_family;

  char *iface;
  if (cfg->conf->bridge[0]) {
    iface = cfg->conf->bridge;
  } else {
    iface = cfg->conf->interface;
  }

  pong_socket_create(iface, af);
  ping_socket_create_rx(iface, af);
  ping_socket_create_tx(iface, af);
}

/*
 * interfaces
 */

/* volatile because it is accessed from multiple threads */
static volatile bool reopen_sockets = true;

void rekey_reopen_sockets(void) {
  sae_debug(SAE_DEBUG_REKEY, "rekey: requesting reopening sockets\n");
  reopen_sockets = true;
}

void rekey_verify_peer(struct candidate *peer) {
  if (reopen_sockets) {
    reopen_sockets = false;
    rekey_sockets_close();
  }

  if (!ALL_SOCKETS_OPEN) {
    rekey_sockets_reopen();
  }

  if (!ALL_SOCKETS_OPEN) {
    sae_debug(SAE_DEBUG_ERR, "rekey: error reopening sockets\n");
    return;
  }

  if (!cfg || !cfg->conf->rekey_enable || !peer) {
    return;
  }

  if (!peer->rekey_ping_timer) {
    sae_debug(SAE_DEBUG_REKEY, "rekey: start rekey for " MACSTR "\n", MAC2STR(peer->peer_mac));
    peer->rekey_ping_count = 0;
    peer->rekey_ok = 0;
    peer->rekey_ok_ping_rx = 0;
    peer->rekey_ping_timer = srv_add_timeout_with_jitter(ctx, SRV_MSEC(cfg->conf->rekey_ping_timeout), ping_tx, peer,
        SRV_MSEC(cfg->conf->rekey_ping_jitter));
    if (!peer->rekey_ping_timer) {
      sae_debug(SAE_DEBUG_ERR, "rekey: failed to schedule ping timeout for " MACSTR "\n", MAC2STR(peer->peer_mac));
    }
  } else {
    sae_debug(SAE_DEBUG_REKEY, "rekey: rekey already running for " MACSTR "\n", MAC2STR(peer->peer_mac));
  }
}

/*
 * lifecycle
 */

void rekey_init(service_context context, struct mesh_node *config) {
  if (cfg) {
    return;
  }

  assert(context);
  assert(config);

  ctx = context;
  cfg = config;

  rekey_reopen_sockets();
}

void rekey_close(void) {
  if (!cfg) {
    return;
  }

  rekey_sockets_close();

  cfg = NULL;
  ctx = NULL;
}
