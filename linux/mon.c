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
#include "service.h"
#include "common.h"
#include "sae.h"

struct interface {
    TAILQ_ENTRY(interface) entry;
    char ifname[IFNAMSIZ];
    int fd;     /* BPF socket */
};
TAILQ_HEAD(bar, interface) interfaces;

service_context srvctx;

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

    frame_control = ieee_order(frame->frame_control);
    type = IEEE802_11_FC_GET_TYPE(frame_control);
    stype = IEEE802_11_FC_GET_STYPE(frame_control);
    if (type == IEEE802_11_FC_TYPE_MGMT) {
        switch (stype) {
            case IEEE802_11_FC_STYPE_BEACON:
                els = frame->beacon.variable;
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
                        printf("received BEACON from " MACSTR " on %s\n", 
                               MAC2STR(frame->sa), inf->ifname);
                        break;
                    }
                    els += el_len;
                    left -= el_len;
                }
                break;
            case IEEE802_11_FC_STYPE_AUTH:
                printf("received %s frame from " MACSTR " to " MACSTR " on %s\n",
                       frame->authenticate.auth_seq == SAE_AUTH_COMMIT ? "COMMIT" : "CONFIRM",
                       MAC2STR(frame->sa), MAC2STR(frame->da), inf->ifname);
                break;
            case IEEE802_11_FC_STYPE_ACTION:
                /* APE exchange */
                printf("received ACTION frame from " MACSTR " to " MACSTR "\n",
                       MAC2STR(frame->sa), MAC2STR(frame->da));
                break;
        }
    }
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
        return;
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, inf->ifname, IFNAMSIZ);
    if (ioctl(inf->fd, SIOCGIFINDEX, &ifr) < 0) {
        fprintf(stderr, "unable to get if index on %s\n", inf->ifname);
        return;
    }

    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);
    if (bind(inf->fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        fprintf(stderr, "unable to bind socket to %s\n", inf->ifname);
        return;
    }

    srv_add_input(srvctx, inf->fd, inf, mgmt_frame_in);
    TAILQ_INSERT_TAIL(&interfaces, inf, entry);
    return;
}

int
main (int argc, char **argv)
{
    int c, ret;
    char confdir[80], conffile[80], mesh_interface[10];
    char str[80], *ptr;
    FILE *fp;

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

    snprintf(conffile, sizeof(conffile), "%s/mon.conf", confdir);
    strcpy(mesh_interface, "lo0");
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
        }
    }

    if (TAILQ_EMPTY(&interfaces)) {
        fprintf(stderr, "%s: no interfaces defined!\n", argv[0]);
        add_interface("lo");
    }
    srv_main_loop(srvctx);

    exit(1);
}
