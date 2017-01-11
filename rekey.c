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

#include "rekey.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/ip.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "common.h"
#include "sae.h"

#define MSEC_PER_USEC       1000

#define EXPLODE_MAC(mac)    ((mac)[0]), ((mac)[1]), ((mac)[2]), ((mac)[3]), ((mac)[4]), ((mac)[5])

#define PACKET_VERSION_PING (0x01)
#define PACKET_VERSION_PONG (0x01)
#define PACKET_TYPE_PING    (0x01)
#define PACKET_TYPE_PONG    (0x02)

typedef struct {
  uint8_t version;
  uint8_t type;
}__attribute__((packed)) packet_header;

typedef struct {
  packet_header header;
  uint8_t ping_mac[ETH_ALEN];
  uint8_t pong_mac[ETH_ALEN];
  in_port_t pong_port;
  uint32_t pong_ip;
}__attribute__((packed)) packet_ping;

typedef struct {
  packet_header header;
  uint8_t pong_mac[ETH_ALEN];
}__attribute__((packed)) packet_pong;

typedef union {
  packet_ping ping;
  packet_pong pong;
}__attribute__((packed)) packet_struct;

static uint8_t my_mac[ETH_ALEN] = { 0 };
static uint32_t my_ip = 0;

static service_context ctx = NULL;
static struct mesh_node *cfg = NULL;

/*
 * helpers
 */

static void *get_socket_address_ip(struct sockaddr *sa) {
  if (sa->sa_family == AF_INET) {
    return &(((struct sockaddr_in*) sa)->sin_addr);
  }

  return &(((struct sockaddr_in6*) sa)->sin6_addr);
}

static bool get_interface_mac_address(int af, const char* iface, uint8_t* mac, uint8_t mac_len) {
  memset(mac, 0, mac_len);

  int sock = socket(af, SOCK_DGRAM, 0);
  if (sock == -1) {
    return false;
  }

  struct ifreq ifr;
  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, iface, sizeof(ifr.ifr_name));
  ifr.ifr_name[sizeof(ifr.ifr_name) - 1] = '\0';

  bool r = (ioctl(sock, SIOCGIFHWADDR, &ifr) != -1);
  if (r) {
    memcpy(mac, ifr.ifr_hwaddr.sa_data, mac_len);
  }

  close(sock);
  return r;
}

static bool get_ip_address(int af, const char* iface, uint32_t* ip) {
  int sock = socket(af, SOCK_DGRAM, 0);
  if (sock == -1) {
    return false;
  }

  struct ifreq ifr;
  memset(&ifr, 0, sizeof(ifr));
  ifr.ifr_addr.sa_family = af;
  strncpy(ifr.ifr_name, iface, sizeof(ifr.ifr_name));
  ifr.ifr_name[sizeof(ifr.ifr_name) - 1] = '\0';

  bool r = (ioctl(sock, SIOCGIFADDR, &ifr) != -1);
  if (r) {
    *ip = (((struct sockaddr_in*) &ifr.ifr_addr)->sin_addr.s_addr);
  }

  close(sock);
  return r;
}

static bool bind_socket_to_interface(int sock, const char* iface) {
  struct ifreq ifr;
  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, iface, sizeof(ifr.ifr_name));
  ifr.ifr_name[sizeof(ifr.ifr_name) - 1] = '\0';

  return !setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, (void *) &ifr, sizeof(ifr));
}

static bool bind_socket(int sock, int af, uint32_t ip, in_port_t port) {
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = af;
  addr.sin_addr.s_addr = ip;
  addr.sin_port = port;

  return !bind(sock, (struct sockaddr*) &addr, sizeof(addr));
}

static int create_socket(int af) {
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

static void pong_tx(int af, uint32_t ip, in_port_t port) {
  char str[INET6_ADDRSTRLEN];

  if (pong_socket == -1) {
    return;
  }

  packet_struct packet;
  packet.pong.header.version = PACKET_VERSION_PONG;
  packet.pong.header.type = PACKET_TYPE_PONG;
  memcpy(packet.pong.pong_mac, my_mac, sizeof(packet.pong.pong_mac));

  struct sockaddr_in dst;
  memset(&dst, 0, sizeof(dst));
  dst.sin_family = af;
  dst.sin_addr.s_addr = ip;
  dst.sin_port = port;

  int bytes = sendto(pong_socket, &packet.pong, sizeof(packet.pong), 0, (struct sockaddr *) &dst, sizeof(dst));

  if (bytes == sizeof(packet.pong)) {
    sae_debug(SAE_DEBUG_PROTOCOL_MSG, "rekey: pong to %s with MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
        inet_ntop(af, &dst.sin_addr.s_addr, str, sizeof(str)), EXPLODE_MAC(my_mac));
    return;
  }

  if (bytes == -1) {
    sae_debug(SAE_DEBUG_ERR, "rekey: pong to %s with MAC %02x:%02x:%02x:%02x:%02x:%02x failed: %s\n",
        inet_ntop(af, &dst.sin_addr.s_addr, str, sizeof(str)), EXPLODE_MAC(my_mac), strerror(errno));
    return;
  }

  sae_debug(SAE_DEBUG_ERR, "rekey: pong to %s with MAC %02x:%02x:%02x:%02x:%02x:%02x sent %d bytes instead of %d\n",
      inet_ntop(af, &dst.sin_addr.s_addr, str, sizeof(str)), EXPLODE_MAC(my_mac), bytes, sizeof(my_mac));
}

static void pong_rx(int sock, void *data) {
  char str[INET6_ADDRSTRLEN];

  uint8_t buffer[sizeof(packet_struct) + 1];
  packet_struct *packet = (packet_struct *) buffer;
  struct sockaddr src;
  socklen_t src_len = sizeof(src);

  int bytes = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *) &src, &src_len);

  if (bytes == sizeof(packet->pong)) {
    if (packet->pong.header.version != PACKET_VERSION_PONG) {
      sae_debug(SAE_DEBUG_ERR, "rekey: pong from %s sent version %u instead of %u, ignored\n",
          inet_ntop(src.sa_family, get_socket_address_ip((struct sockaddr *) &src), str, sizeof(str)),
          packet->pong.header.version, PACKET_VERSION_PONG);
      return;
    }

    if (packet->pong.header.type != PACKET_TYPE_PONG) {
      sae_debug(SAE_DEBUG_ERR, "rekey: pong from %s sent type %u instead of %u, ignored\n",
          inet_ntop(src.sa_family, get_socket_address_ip((struct sockaddr *) &src), str, sizeof(str)),
          packet->pong.header.type, PACKET_TYPE_PONG);
      return;
    }

    struct candidate *peer = find_peer(packet->pong.pong_mac, 1);
    if (!peer) {
      sae_debug(SAE_DEBUG_ERR, "rekey: pong from %s sent unknown peer MAC %02x:%02x:%02x:%02x:%02x:%02x, ignored\n",
          inet_ntop(src.sa_family, get_socket_address_ip((struct sockaddr *) &src), str, sizeof(str)),
          EXPLODE_MAC(packet->pong.pong_mac));
      return;
    }

    /* keys are installed correctly */

    sae_debug(SAE_DEBUG_PROTOCOL_MSG,
        "rekey: pong from %s sent known peer MAC %02x:%02x:%02x:%02x:%02x:%02x, keys are installed correctly\n",
        inet_ntop(src.sa_family, get_socket_address_ip((struct sockaddr *) &src), str, sizeof(str)),
        EXPLODE_MAC(packet->pong.pong_mac));

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

  sae_debug(SAE_DEBUG_ERR, "rekey: pong from %s sent %d bytes instead of %d\n",
      inet_ntop(src.sa_family, get_socket_address_ip((struct sockaddr *) &src), str, sizeof(str)), bytes,
      sizeof(packet->pong));
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
  pong_socket = create_socket(af);
  if (pong_socket == -1) {
    goto err;
  }

  if (!bind_socket_to_interface(pong_socket, iface)) {
    goto err;
  }

  if (!bind_socket(pong_socket, af, htonl(INADDR_ANY), cfg->conf->rekey_pong_port)) {
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
  return;
}

/*
 * ping receive
 */

static int ping_socket_rx = -1;

static void ping_rx(int sock, void *data) {
  char str[INET6_ADDRSTRLEN];

  uint8_t buffer[sizeof(packet_struct) + 1];
  packet_struct *packet = (packet_struct *) buffer;
  struct sockaddr src;
  socklen_t src_len = sizeof(src);

  int bytes = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *) &src, &src_len);

  if (bytes == sizeof(packet->ping)) {
    if (packet->ping.header.version != PACKET_VERSION_PING) {
      sae_debug(SAE_DEBUG_ERR, "rekey: ping from %s sent version %u instead of %u, ignored\n",
          inet_ntop(src.sa_family, get_socket_address_ip((struct sockaddr *) &src), str, sizeof(str)),
          packet->ping.header.version, PACKET_VERSION_PING);
      return;
    }

    if (packet->ping.header.type != PACKET_TYPE_PING) {
      sae_debug(SAE_DEBUG_ERR, "rekey: ping from %s sent type %u instead of %u, ignored\n",
          inet_ntop(src.sa_family, get_socket_address_ip((struct sockaddr *) &src), str, sizeof(str)),
          packet->ping.header.type, PACKET_TYPE_PING);
      return;
    }

    if (memcmp(packet->ping.ping_mac, my_mac, sizeof(my_mac))) {
      sae_debug(SAE_DEBUG_ERR,
          "rekey: ping from %s sent MAC %02x:%02x:%02x:%02x:%02x:%02x instead of %02x:%02x:%02x:%02x:%02x:%02x, ignored\n",
          inet_ntop(src.sa_family, get_socket_address_ip((struct sockaddr *) &src), str, sizeof(str)),
          EXPLODE_MAC(packet->ping.ping_mac), EXPLODE_MAC(my_mac));
      return;
    }

    struct candidate *peer = find_peer(packet->ping.pong_mac, 1);
    if (!peer) {
      sae_debug(SAE_DEBUG_ERR, "rekey: ping from %s sent unknown peer MAC %02x:%02x:%02x:%02x:%02x:%02x, ignored\n",
          inet_ntop(src.sa_family, get_socket_address_ip((struct sockaddr *) &src), str, sizeof(str)),
          EXPLODE_MAC(packet->ping.ping_mac));
      return;
    }

    /* re-authenticate when we concluded that keys are installed correctly but we are still receiving pings */
    if (peer->rekey_ok) {
      peer->rekey_ok_ping_rx++;
      if (peer->rekey_ok_ping_rx > cfg->conf->rekey_ok_ping_count_max) {
        sae_debug(SAE_DEBUG_ERR,
            "rekey: too many pings from %s while considering keys correctly installed, doing reauth\n",
            inet_ntop(src.sa_family, get_socket_address_ip((struct sockaddr *) &src), str, sizeof(str)));
        peer->rekey_ok_ping_rx = 0;
        do_reauth(peer);
        return;
      }
    }

    sae_debug(SAE_DEBUG_PROTOCOL_MSG, "rekey: ping from %s, replying\n",
        inet_ntop(src.sa_family, get_socket_address_ip((struct sockaddr *) &src), str, sizeof(str)));

    pong_tx(cfg->conf->rekey_multicast_group_family, packet->ping.pong_ip, cfg->conf->rekey_pong_port);
    return;
  }

  if (bytes == -1) {
    sae_debug(SAE_DEBUG_ERR, "rekey: ping rx failed: %s\n", strerror(errno));
    return;
  }

  sae_debug(SAE_DEBUG_ERR, "rekey: ping from %s sent %d bytes instead of %d\n",
      inet_ntop(src.sa_family, get_socket_address_ip((struct sockaddr *) &src), str, sizeof(str)), bytes,
      sizeof(packet->ping));
}

static void ping_socket_close_rx(int af) {
  if (ping_socket_rx == -1) {
    return;
  }

  struct ip_mreq mreq;
  memset(&mreq, 0, sizeof(mreq));
  mreq.imr_multiaddr.s_addr = cfg->conf->rekey_multicast_group_address.v4.s_addr;
  mreq.imr_interface.s_addr = htonl(INADDR_ANY);

  (void) setsockopt(ping_socket_rx, IPPROTO_IP, IP_DROP_MEMBERSHIP, &mreq, sizeof(mreq));

  srv_rem_input(ctx, ping_socket_rx);

  close(ping_socket_rx);
  ping_socket_rx = -1;
}

static void ping_socket_create_rx(const char* iface, int af) {
  ping_socket_rx = create_socket(af);
  if (ping_socket_rx == -1) {
    goto err;
  }

  if (!bind_socket_to_interface(ping_socket_rx, iface)) {
    goto err;
  }

  if (!bind_socket(ping_socket_rx, af, htonl(INADDR_ANY), cfg->conf->rekey_ping_port)) {
    goto err;
  }

  uint8_t loopback = 0;
  if (setsockopt(ping_socket_rx, IPPROTO_IP, IP_MULTICAST_LOOP, &loopback, sizeof(loopback)) == -1) {
    goto err;
  }

  struct ip_mreq mreq;
  memset(&mreq, 0, sizeof(mreq));
  mreq.imr_multiaddr.s_addr = cfg->conf->rekey_multicast_group_address.v4.s_addr;
  mreq.imr_interface.s_addr = htonl(INADDR_ANY);

  if (setsockopt(ping_socket_rx, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) == -1) {
    goto err;
  }

  if (srv_add_input(ctx, ping_socket_rx, NULL, ping_rx)) {
    goto err;
  }

  return;

  err: ping_socket_close_rx(af);
  return;
}

/*
 * ping send
 */

static int ping_socket_tx = -1;

static void ping_tx(timerid id, void *data) {
  if (!data) {
    return;
  }

  struct candidate *peer = (struct candidate *) data;

  peer->rekey_ping_count++;

  /* check whether we did too many pings */
  if (peer->rekey_ping_count > cfg->conf->rekey_ping_count_max) {
    srv_rem_timeout(ctx, peer->rekey_ping_timer);
    peer->rekey_ping_timer = 0;
    peer->rekey_ping_count = 0;

    /* check whether we can do another reauth */
    if (peer->rekey_reauth_count < cfg->conf->rekey_reauth_count_max) {
      rekey_reopen_sockets();
      peer->rekey_reauth_count++;
      sae_debug(SAE_DEBUG_PROTOCOL_MSG, "rekey: reauthentication #%u for %02x:%02x:%02x:%02x:%02x:%02x\n",
          peer->rekey_reauth_count, EXPLODE_MAC(peer->peer_mac));
      do_reauth(peer);
    }

    return;
  }

  /* ping */

  packet_struct packet;
  packet.ping.header.version = PACKET_VERSION_PING;
  packet.ping.header.type = PACKET_TYPE_PING;
  memcpy(packet.ping.ping_mac, peer->peer_mac, sizeof(packet.ping.ping_mac));
  memcpy(packet.ping.pong_mac, my_mac, sizeof(packet.ping.pong_mac));
  packet.ping.pong_port = cfg->conf->rekey_pong_port;
  memcpy(&packet.ping.pong_ip, &my_ip, sizeof(packet.ping.pong_ip));

  struct sockaddr_in dst;
  memset(&dst, 0, sizeof(dst));
  dst.sin_family = cfg->conf->rekey_multicast_group_family;
  dst.sin_addr.s_addr = cfg->conf->rekey_multicast_group_address.v4.s_addr;
  dst.sin_port = cfg->conf->rekey_ping_port;

  int bytes = sendto(ping_socket_tx, &packet.ping, sizeof(packet.ping), 0, (struct sockaddr *) &dst, sizeof(dst));

  if (bytes == sizeof(packet.ping)) {
    sae_debug(SAE_DEBUG_PROTOCOL_MSG, "rekey: ping #%u to %02x:%02x:%02x:%02x:%02x:%02x\n", peer->rekey_ping_count,
        EXPLODE_MAC(peer->peer_mac));
    srv_rem_timeout(ctx, peer->rekey_ping_timer);
    peer->rekey_ping_timer = srv_add_timeout(ctx, cfg->conf->rekey_ping_timeout * MSEC_PER_USEC, ping_tx, peer);
    if (!peer->rekey_ping_timer) {
      sae_debug(SAE_DEBUG_ERR, "rekey: ping #%u to %02x:%02x:%02x:%02x:%02x:%02x failed to reschedule ping timer\n",
          peer->rekey_ping_count, EXPLODE_MAC(peer->peer_mac));
    }
    return;
  }

  if (bytes == -1) {
    sae_debug(SAE_DEBUG_ERR, "rekey: ping send failed: %s\n", strerror(errno));
    return;
  }

  sae_debug(SAE_DEBUG_ERR, "rekey: ping sent %d bytes instead of %d\n", bytes, sizeof(packet.ping));
}

static void ping_socket_close_tx(void) {
  if (ping_socket_tx == -1) {
    return;
  }

  close(ping_socket_tx);
  ping_socket_tx = -1;
}

static void ping_socket_create_tx(const char* iface, int af) {
  ping_socket_tx = create_socket(af);
  if (ping_socket_tx == -1) {
    goto err;
  }

  if (!bind_socket_to_interface(ping_socket_tx, iface)) {
    goto err;
  }

  uint8_t loopback = 0;
  if (setsockopt(ping_socket_tx, IPPROTO_IP, IP_MULTICAST_LOOP, &loopback, sizeof(loopback)) == -1) {
    goto err;
  }

  int ttl = 1;
  if (setsockopt(ping_socket_tx, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl))) {
    goto err;
  }

  if (fcntl(ping_socket_tx, F_SETFL, O_NDELAY)) {
    goto err;
  }

  return;

  err: ping_socket_close_tx();
  return;
}

/*
 * sockets
 */

#define ALL_SOCKETS_OPEN ((ping_socket_tx != -1) && (ping_socket_rx != -1) && (pong_socket != -1))

static void rekey_sockets_close(int af) {
  ping_socket_close_tx();
  ping_socket_close_rx(af);
  pong_socket_close();
}

static void rekey_sockets_reopen(void) {
  int af = cfg->conf->rekey_multicast_group_family;

  rekey_sockets_close(af);

  if (!get_interface_mac_address(af, cfg->conf->interface, my_mac, sizeof(my_mac))) {
    goto err;
  }

  bool bridge = (cfg->conf->bridge[0] != '\0');
  char *iface = NULL;

  memset(&my_ip, 0, sizeof(my_ip));
  bool ip_ok = false;

  if (bridge) {
    iface = cfg->conf->bridge;
    ip_ok = get_ip_address(af, iface, &my_ip);
    cfg->conf->rekey_interface_is_bridge = ip_ok;
  }

  if (!ip_ok) {
    bridge = false;
    iface = cfg->conf->interface;
    cfg->conf->rekey_interface_is_bridge = false;
    ip_ok = get_ip_address(af, iface, &my_ip);
  }

  if (!ip_ok) {
    if (bridge) {
      sae_debug(SAE_DEBUG_ERR, "rekey: neither bridge '%s' nor interface '%s' have an IP address\n", cfg->conf->bridge,
          cfg->conf->interface);
    } else {
      sae_debug(SAE_DEBUG_ERR, "rekey: interface '%s' doesn't have an IP address\n", cfg->conf->interface);
    }

    goto err;
  }

  pong_socket_create(iface, af);
  ping_socket_create_rx(iface, af);
  ping_socket_create_tx(iface, af);

  if (ALL_SOCKETS_OPEN) {
    return;
  }

  err: rekey_sockets_close(af);
  memset(&my_ip, 0, sizeof(my_ip));
  memset(my_mac, 0, sizeof(my_mac));
}

/*
 * lifecycle
 */

void rekey_init(service_context context, struct mesh_node *config) {
  ctx = context;
  cfg = config;
}

void rekey_close(void) {
  int af = cfg->conf->rekey_multicast_group_family;

  rekey_sockets_close(af);

  cfg = NULL;
  ctx = NULL;
}

/*
 * interfaces
 */

/* volatile because it is accessed from multiple threads */
static volatile bool reopen_sockets = false;

void rekey_reopen_sockets(void) {
  reopen_sockets = true;
}

void rekey_verify_peer(struct candidate *peer) {
  if (!cfg || !cfg->conf->rekey_enable || !peer) {
    return;
  }

  if (reopen_sockets || !ALL_SOCKETS_OPEN) {
    sae_debug(SAE_DEBUG_PROTOCOL_MSG, "rekey: reopening sockets\n");
    reopen_sockets = false;
    rekey_sockets_reopen();
  }

  if (!ALL_SOCKETS_OPEN) {
    sae_debug(SAE_DEBUG_ERR, "rekey: failed to open sockets\n");
    return;
  }

  if (!peer->rekey_ping_timer) {
    sae_debug(SAE_DEBUG_PROTOCOL_MSG, "rekey: trigger rekey\n");
    peer->rekey_ping_count = 0;
    peer->rekey_ok = 0;
    peer->rekey_ok_ping_rx = 0;
    peer->rekey_ping_timer = srv_add_timeout_with_jitter(ctx, cfg->conf->rekey_ping_timeout * MSEC_PER_USEC, ping_tx,
        peer, cfg->conf->rekey_ping_jitter * MSEC_PER_USEC);
    if (!peer->rekey_ping_timer) {
      sae_debug(SAE_DEBUG_ERR, "rekey: failed to schedule ping timer\n");
    }
  }
}
