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

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_tun.h>
#include <openssl/rand.h>
#include <limits.h>
#include "service.h"
#include "common.h"
#include "sae.h"
#include "ampe.h"

struct interface {
    TAILQ_ENTRY(interface) entry;
    char ifname[IFNAMSIZ];
    unsigned char bssid[ETH_ALEN];
    int fd;     /* BPF socket */
};
TAILQ_HEAD(bar, interface) interfaces;

service_context srvctx;
char mesh_ssid[33];
static int debug = 0, passive = 0, beacon = 5;

static void
dump_ssid (struct ieee80211_mgmt_frame *frame, int len)
{
    char el_id, el_len, ssid[33];
    unsigned char *ptr;
    int left;

    ptr = frame->beacon.u.var8;
    left = len - (IEEE802_11_HDR_LEN + sizeof(frame->beacon));
    while (left > 2) {
        el_id = *ptr++;
        left--;
        el_len = *ptr++;
        left--;
        if (el_len > left) {
            return;
        }
        if (el_id == IEEE802_11_IE_SSID) {
            if (el_len > 32) {
                return;
            }
            memset(ssid, 0, sizeof(ssid));
            memcpy(ssid, ptr, el_len);
            break;
        }
    }
}

static void
mgmt_frame_in (int fd, void *data)
{
    struct interface *inf = (struct interface *)data;
    char el_id, el_len, ssid[33];
    unsigned char buf[2048], *els;
    struct ieee80211_mgmt_frame *frame;
    unsigned short frame_control;
    int type, stype, framesize, left;
    struct sockaddr_ll from;
    socklen_t fromlen;

    fromlen = sizeof(from);
    if ((framesize = recvfrom(fd, buf, sizeof(buf), MSG_TRUNC,
                              (struct sockaddr *)&from, &fromlen)) < 0) {
        fprintf(stderr, "can't read off bpf socket!\n");
        perror("read");
        return;
    }
    /*
     * we don't want to see outgoing packets otherwise we'll see
     * everything twice
     */
    if (from.sll_pkttype == PACKET_OUTGOING) {
        return;
    }

    frame = (struct ieee80211_mgmt_frame *)buf;
    if (memcmp(frame->sa, inf->bssid, ETH_ALEN) == 0) {
        return;
    }

    frame_control = ieee_order(frame->frame_control);
    type = IEEE802_11_FC_GET_TYPE(frame_control);
    stype = IEEE802_11_FC_GET_STYPE(frame_control);
    if (debug) {
        if (stype == IEEE802_11_FC_STYPE_BEACON) {
            dump_ssid(frame, framesize);
        }
    }

    if (type == IEEE802_11_FC_TYPE_MGMT) {
        switch (stype) {
            case IEEE802_11_FC_STYPE_BEACON:
                els = frame->beacon.u.var8;
                left = framesize - (IEEE802_11_HDR_LEN + sizeof(frame->beacon));
                /*
                 * els is the next IE in the beacon,
                 * left is how much is left to read in the beacon
                 */
                while (left > 2) {
                    el_id = *els++;
                    left--;
                    el_len = *els++;
                    left--;
                    if (el_len > left) {
                        /*
                         * someone's trying to mess with us...
                         */
                        break;
                    }
                    if (el_id == IEEE802_11_IE_SSID) {
                        if (el_len > 32) {
                            /*
                             * again with the messing...
                             */
                            break;
                        }
                        memset(ssid, 0, sizeof(ssid));
                        memcpy(ssid, els, el_len);
                        /*
                         * if it's not an interesting ssid then ignore the beacon
                         * otherwise send it off to SAE.
                         */
                        if ((el_len == 0) || memcmp(ssid, mesh_ssid, strlen(ssid))) {
                            break;
                        }
                        if (process_mgmt_frame(frame, framesize, inf->bssid, NULL) < 0) {
                            fprintf(stderr, "error processing beacon for %s from " MACSTR "\n",
                                    ssid, MAC2STR(frame->sa));
                        }
                        break;
                    }
                    els += el_len;
                    left -= el_len;
                }
                break;
            case IEEE802_11_FC_STYPE_AUTH:
                if (memcmp(frame->da, inf->bssid, ETH_ALEN) == 0) {
                    if (process_mgmt_frame(frame, framesize, inf->bssid, NULL) < 0) {
                        fprintf(stderr, "error processing AUTH frame from " MACSTR "\n",
                                MAC2STR(frame->sa));
                    }
                }
                break;
            case IEEE802_11_FC_STYPE_ACTION:
                /* APE exchange */
                break;
        }
    }
}

/*
 * service provided to sae: sending of management frames over-the-air
 */
int meshd_write_mgmt (char *data, int len)
{
    struct interface *inf = NULL;
    struct ieee80211_mgmt_frame *frame = (struct ieee80211_mgmt_frame *)data;

    TAILQ_FOREACH(inf, &interfaces, entry) {
        if (memcmp(frame->sa, inf->bssid, ETH_ALEN) == 0) {
            break;
        }
    }
    if (inf == NULL) {
        fprintf(stderr, "can't find " MACSTR " to send mgmt frame!\n",
                MAC2STR(frame->sa));
        return -1;
    }
    if (write(inf->fd, data, len) < 0) {
        fprintf(stderr, "unable to write management frame!\n");
        return -1;
    }
    return len;
}

/*
 * fin()
 *      sae has finished for the specified MAC address. If the reason
 *      is because it was successful, there will be a key (PMK) to plumb
 */
void
fin (unsigned short reason, unsigned char *mac, unsigned char *key, int keylen)
{
    printf("status of " MACSTR " is %d, ", MAC2STR(mac), reason);
    if ((reason == 0) && (key != NULL) && (keylen > 0)) {
        printf("plumb the %d byte key into the kernel now!\n", keylen);
    } else {
        printf("(an error)\n");
    }
}

void peer_created(unsigned char *peer)
{
    printf("SAE notification that a peer was created\n");
}

int set_plink_state(unsigned char *peer, int state, void *cookie)
{
	printf("TODO: implement set_plink_state\n");
	return 0;
}

void estab_peer_link(unsigned char *peer,
        unsigned char *mtk, int mtk_len,
        unsigned char *peer_mgtk, int peer_mgtk_len,
        unsigned int mgtk_expiration,
        unsigned char *peer_igtk, int peer_igtk_len, int peer_igtk_keyid,
        unsigned char *rates,
        unsigned short rates_len,
        void *cookie)
{
    printf("TODO: implement estab_peer_link\n");
}

int meshd_set_mesh_conf(struct mesh_node *mesh, uint32_t changed)
{
	printf("TODO: implement meshd_set_mesh_conf, or don't. Just build\n");
	return 0;
}

static void
add_interface (char *ptr)
{
    struct interface *inf;
    struct ifreq ifr;
    struct sockaddr_ll sll;

    TAILQ_FOREACH(inf, &interfaces, entry) {
        if (memcmp(&inf->ifname, ptr, strlen(ptr)) == 0) {
            printf("%s is already on the list!\n", ptr);
            return;
        }
    }
    if ((inf = (struct interface *)malloc(sizeof(struct interface))) == NULL) {
        fprintf(stderr, "failed to malloc space for new interface %s!\n", ptr);
        return;
    }
    strncpy(inf->ifname, ptr, strlen(ptr));

    /*
     * see if this is a loopback interface
     */
    if ((inf->fd = socket(PF_PACKET, SOCK_RAW, 0)) < 0) {
        fprintf(stderr, "unable to get raw socket to determine interface flags!\n");
        free(inf);
        return;
    }
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, inf->ifname, IFNAMSIZ);
    if (ioctl(inf->fd, SIOCGIFFLAGS, &ifr) < 0) {
        fprintf(stderr, "unable to get ifflags for %s!\n", ptr);
        /*
         * should this be fatal? Dunno, let's just assume it's _not_ loopback
         */
        ifr.ifr_flags = 0;
    }
    if ((ifr.ifr_flags & IFF_LOOPBACK) == 0) {
        fprintf(stderr, "only works on loopback for now!\n");
        free(inf);
        return;
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, inf->ifname, IFNAMSIZ);
    if (ioctl(inf->fd, SIOCGIFINDEX, &ifr) < 0) {
        fprintf(stderr, "unable to get if index on %s\n", inf->ifname);
        free(inf);
        return;
    }

    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);
    if (bind(inf->fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        fprintf(stderr, "unable to bind socket to %s\n", inf->ifname);
        free(inf);
        return;
    }

    /*
     * make up a bssid for the loopback interface
     */
    RAND_pseudo_bytes(&inf->bssid[0], ETH_ALEN);

    srv_add_input(srvctx, inf->fd, inf, mgmt_frame_in);
    TAILQ_INSERT_TAIL(&interfaces, inf, entry);
    return;
}

/*
 * send_beacon()
 *      beacons are normally sent out automagically by the radio but if we're
 *      simulating this protocol over the loopback we need to send them here.
 */
static void
send_beacon (timerid tid, void *data)
{
    struct interface *inf = (struct interface *)data;
    struct ieee80211_mgmt_frame *frame;
    unsigned char buf[2048], *el;
    unsigned char broadcast[ETH_ALEN] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    int len, blen;

    if (inf == NULL) {
        return;
    }
    memset(buf, 0, sizeof(buf));
    /*
     * make a pseudo-beacon
     */
    frame = (struct ieee80211_mgmt_frame *)buf;
    frame->frame_control = ieee_order((IEEE802_11_FC_TYPE_MGMT << 2 | IEEE802_11_FC_STYPE_BEACON << 4));
    memcpy(frame->da, broadcast, ETH_ALEN);
    memcpy(frame->sa, inf->bssid, ETH_ALEN);
    memcpy(frame->bssid, inf->bssid, ETH_ALEN);

    /*
     * not a truely valid beacon but so what, this is a simulator and
     * all we really care about is the ssid
     */
    el = frame->beacon.u.var8;
    *el = IEEE802_11_IE_SSID;
    el++;
    *el = strlen(mesh_ssid);
    el++;
    memcpy(el, mesh_ssid, strlen(mesh_ssid));
    el += strlen(mesh_ssid);

    len = el - buf;
    blen = write(inf->fd, buf, len);
    if (blen < 0) {
        perror("write");
    }
    srv_add_timeout(srvctx, SRV_SEC(beacon), send_beacon, inf);
    return;
}

int
main (int argc, char **argv)
{
    int c, ret;
    struct interface *inf;
    struct sigaction act;
    char confdir[PATH_MAX], conffile[PATH_MAX], mesh_interface[IFNAMSIZ];
    char str[80], *ptr;
    FILE *fp;
    struct sae_config config;

    strcpy(confdir, "/usr/local/config");
    for (;;) {
        c = getopt(argc, argv, "hI:b");
        if (c < 0) {
            break;
        }
        switch (c) {
            case 'I':
                snprintf(confdir, sizeof(confdir), "%s", optarg);
                break;
            case 'b':
                /*
                 * detach from controlling terminal and redirect output to /dev/null.
                 * meshd will not cd to "/" to allow -I to specify relative directories.
                 */
                if (daemon(1, 0)) {
                    perror("daemon");
                    fprintf(stderr, "%s: unable to daemonize!\n", argv[0]);
                    exit(1);
                }
                break;
            default:
            case 'h':
                fprintf(stderr,
                        "USAGE: %s [-hIb]\n\t-h  show usage, and exit\n"
                        "\t-I  directory of config files\n"
                        "\t-b  run in the background\n",
                        argv[0]);
                exit(1);

        }
    }

    TAILQ_INIT(&interfaces);
    if ((srvctx = srv_create_context()) == NULL) {
        fprintf(stderr, "%s: cannot create service context!\n", argv[0]);
        exit(1);
    }

    snprintf(conffile, sizeof(conffile), "%s/meshd.conf", confdir);
    strcpy(mesh_ssid, "meshd");
    strcpy(mesh_interface, "lo0");
    debug = 0;
    passive = 0;
    if ((fp = fopen(conffile, "r")) != NULL) {
        while (!feof(fp)) {
            if (fgets(str, sizeof(str), fp) == 0) {
                continue;
            }
            if ((ret = parse_buffer(str, &ptr)) < 0) {
                break;
            }
            if (ret == 0) {
                continue;
            }
            if (strncmp(str, "interface", strlen("interface")) == 0) {
                add_interface(ptr);
            }
            if (strncmp(str, "ssid", strlen("ssid")) == 0) {
                strcpy(mesh_ssid, ptr);
            }
            if (strncmp(str, "passive", strlen("passive")) == 0) {
                passive = atoi(ptr);
            }
            if (strncmp(str, "beacon", strlen("beacon")) == 0) {
                beacon = atoi(ptr);
            }
            if (strncmp(str, "debug", strlen("debug")) == 0) {
                debug = atoi(ptr);
            }
        }
    }

    if (TAILQ_EMPTY(&interfaces)) {
        fprintf(stderr, "%s: no interfaces defined!\n", argv[0]);
        add_interface("lo");
    }
    printf("interfaces and MAC addresses:\n");
    TAILQ_FOREACH(inf, &interfaces, entry) {
        /*
         * no radio to configure but just set a timer for these
         * phony beacons
         */
        printf("\t%s: " MACSTR "\n", inf->ifname, MAC2STR(inf->bssid));
        if (passive == 0) {
            (void)srv_add_timeout(srvctx, SRV_SEC(beacon), send_beacon, inf);
        }
    }

    /*
     * initialize SAE...
     */
    sae_parse_config(confdir, &config);
    if (sae_initialize(mesh_ssid, &config) < 0) {
        fprintf(stderr, "%s: cannot configure SAE, check config file!\n", argv[0]);
        exit(1);
    }

    /*
     * re-read the SAE config upon receipt of HUP
     */
#if 0
    act.sa_handler = sae_read_config;
    sigaction(SIGHUP, &act, NULL);
#endif
    act.sa_handler = sae_dump_db;
    sigaction(SIGUSR1, &act, NULL);

    srv_main_loop(srvctx);

    exit(1);
}
