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
#include <net/if_dl.h>
#include <net/if_media.h>
#include <net/bpf.h>
#include <net/route.h>
#include <net80211/ieee80211.h>
#include <net80211/ieee80211_ioctl.h>
#include <net80211/ieee80211_freebsd.h>
#include <openssl/rand.h>
#include "service.h"
#include "common.h"
#include "sae.h"

struct interface {
    TAILQ_ENTRY(interface) entry;
    unsigned char ifname[IFNAMSIZ];
    unsigned char bssid[ETH_ALEN];
    unsigned char is_loopback;
    int fd;     /* BPF socket */
};
TAILQ_HEAD(bar, interface) interfaces;

service_context srvctx;
unsigned char mesh_ssid[33];
static int debug = 0, passive = 0, beacon = 5;

static void
dump_ssid (struct ieee80211_mgmt_frame *frame, int len)
{
    char el_id, el_len, ssid[33];
    unsigned char *ptr;
    int left;

    ptr = frame->beacon.variable;
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
bpf_in (int fd, void *data)
{
    struct interface *inf = (struct interface *)data;
    char el_id, el_len, ssid[33];
    unsigned char buf[2048], *ptr, *els;
    struct bpf_hdr *hdr;
    struct ieee80211_mgmt_frame *frame;
    unsigned short frame_control;
    int type, stype, len, framesize, left;

    if ((len = read(fd, buf, sizeof(buf))) < 0) {
        fprintf(stderr, "can't read off bpf socket!\n");
        perror("read");
        return;
    }

    ptr = buf;
    while (len > 0) {
        hdr = (struct bpf_hdr *)ptr;
        /*
         * if loopback skip over the BPF's pseudo header.
         */
        if (inf->is_loopback) {
            frame = (struct ieee80211_mgmt_frame *)(ptr + hdr->bh_hdrlen + sizeof(unsigned long));
            framesize = hdr->bh_datalen - sizeof(unsigned long);
        } else {
            frame = (struct ieee80211_mgmt_frame *)(ptr + hdr->bh_hdrlen);
            framesize = hdr->bh_datalen;
        }
        if (framesize > len) {
            fprintf(stderr, "something is seriously fucked up! read %d, frame is %d\n",
                    len, framesize);
            return;
        }

        /*
         * even though we explicitly state that we don't want to see our
         * own frames the "multicast" "beacons" we send over loopback
         * seem to get delivered to us anyway. Drop them.
         */
        if (memcmp(frame->sa, inf->bssid, ETH_ALEN) == 0) {
            /*
             * there might be another frame...
             */
            len -= BPF_WORDALIGN(hdr->bh_hdrlen + hdr->bh_caplen);
            ptr += BPF_WORDALIGN(hdr->bh_hdrlen + hdr->bh_caplen);
            continue;
        }

        frame_control = ieee_order(frame->frame_control);
        type = IEEE802_11_FC_GET_TYPE(frame_control);
        stype = IEEE802_11_FC_GET_STYPE(frame_control);
        if (debug) {
            if (stype == IEEE802_11_FC_STYPE_BEACON) {
                dump_ssid(frame, hdr->bh_datalen);
            }
        }

        if (type == IEEE802_11_FC_TYPE_MGMT) {
            switch (stype) {
                case IEEE802_11_FC_STYPE_BEACON:
                    if (passive) {
                        break;
                    }
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
                            /*
                             * if it's not an interesting ssid then ignore the beacon
                             * otherwise send it off to SAE.
                             */
                            if ((el_len == 0) || memcmp(ssid, mesh_ssid, strlen(ssid))) {
                                break;
                            }
                            if (process_mgmt_frame(frame, framesize, inf->bssid) < 0) {
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
                        if (process_mgmt_frame(frame, framesize, inf->bssid) < 0) {
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
        /*
         * there might be another frame...
         */
        len -= BPF_WORDALIGN(hdr->bh_hdrlen + hdr->bh_caplen);
        ptr += BPF_WORDALIGN(hdr->bh_hdrlen + hdr->bh_caplen);
    }
}

/*
 * service provided to sae: sending of management frames over-the-air
 */
int meshd_write_mgmt (char *data, int len)
{
    char buf[2048];
    struct interface *inf = NULL;
    struct ieee80211_mgmt_frame *frame = (struct ieee80211_mgmt_frame *)data;
    unsigned long af;

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
    if (inf->is_loopback) {
        /*
         * add the loopback pseudo-header to indicate the AF
         */
        memset(buf, 0, sizeof(buf));
        af = AF_INET;
        memcpy(buf, &af, sizeof(unsigned long));
        memcpy(buf + sizeof(unsigned long), data, len);
        if (write(inf->fd, buf, len + sizeof(unsigned long)) < 0) {
            fprintf(stderr, "unable to write management frame!\n");
            return -1;
        }
    } else {
        if (write(inf->fd, data, len) < 0) {
            fprintf(stderr, "unable to write management frame!\n");
            return -1;
        }
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

static void
add_interface (unsigned char *ptr)
{
    struct interface *inf;
    char bpfdev[sizeof "/dev/bpfXXXXXXXX"];
    int s, var, bpfnum = 0;
    struct ifreq ifr;
    struct bpf_program bpf_filter;
    struct bpf_insn allofit[] = {
        /*
         * a bpf filter to get beacons, authentication and action frames 
         */
        BPF_STMT(BPF_LD+BPF_B+BPF_ABS, 0),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x80, 0, 1),    /* beacon */
        BPF_STMT(BPF_RET+BPF_K, (unsigned int) -1),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0xb0, 0, 1),    /* auth */
        BPF_STMT(BPF_RET+BPF_K, (unsigned int) -1),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0xd0, 0, 1),    /* action for APE */
        BPF_STMT(BPF_RET+BPF_K, (unsigned int) -1),     /* coming soon :-) */
        BPF_STMT(BPF_RET+BPF_K, 0),
    };
    struct bpf_insn sim80211[] = {
        /*
         * for loopback interfaces, just grab everything
         */
        { 0x6, 0, 0, 0x00000800 },
    };

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
    if ((s = socket(PF_INET, SOCK_RAW, 0)) < 0) {
        fprintf(stderr, "unable to get raw socket to determine interface flags!\n");
        return;
    }
    memset(&ifr, 0, sizeof(ifr));
    strlcpy(ifr.ifr_name, inf->ifname, IFNAMSIZ);
    if (ioctl(s, SIOCGIFFLAGS, &ifr) < 0) {
        fprintf(stderr, "unable to get ifflags for %s!\n", ptr);
        /*
         * should this be fatal? Dunno, let's just assume it's _not_ loopback
         */
        ifr.ifr_flags = 0;
    }
    close(s);
    if (ifr.ifr_flags & IFF_LOOPBACK) {
        inf->is_loopback = 1;
    }
    /*
     * find a non-busy bpf device
     */
    do {
        (void)snprintf(bpfdev, sizeof(bpfdev), "/dev/bpf%d", bpfnum++);
        inf->fd = open(bpfdev, O_RDWR);
    } while (inf->fd < 0 && errno == EBUSY);
    if (inf->fd < 0) {
        fprintf(stderr, "error opening bpf device %s!\n", bpfdev);
        perror("open");
        exit(1);
    }

    var = 2048;
    if (ioctl(inf->fd, BIOCSBLEN, &var)) {
        fprintf(stderr, "can't set bpf buffer length!\n");
        exit(1);
    }
    memset(&ifr, 0, sizeof(ifr));
    strlcpy(ifr.ifr_name, inf->ifname, IFNAMSIZ);
    printf("setting bpf%d to interface %s, %s\n", bpfnum-1, ifr.ifr_name,
           inf->is_loopback ? "loopback" : "not loopback");
    if (ioctl(inf->fd, BIOCSETIF, &ifr)) {
        fprintf(stderr, "unable to set bpf!\n");
        exit(1);
    }
    if (ioctl(inf->fd, BIOCPROMISC, &ifr)) {
        fprintf(stderr, "can't set bpf to be promiscuous!\n");
        exit(1);
    }
    var = 1;
    if (ioctl(inf->fd, BIOCIMMEDIATE, &var)) {
        fprintf(stderr, "can't set bpf to be immediate!\n");
        exit(1);
    }
    var = 0;
    if (ioctl(inf->fd, BIOCSSEESENT, &var)) {
        fprintf(stderr, "can't tell bpf to ignore our own packets!\n");
        /* not really fatal, just bothersome */
    }
    if (inf->is_loopback) {
        /*
         * make up a bssid for the loopback interface
         */
        RAND_pseudo_bytes(&inf->bssid[0], ETH_ALEN);
        var = DLT_NULL;
        if (ioctl(inf->fd, BIOCSDLT, &var)) {
            fprintf(stderr, "can't set bpf link layer type!\n");
            exit(1);
        }
        bpf_filter.bf_len = sizeof(sim80211) / sizeof(struct bpf_insn);
        bpf_filter.bf_insns = sim80211;
        if (ioctl(inf->fd, BIOCSETF, &bpf_filter)) {
            fprintf(stderr, "can't set bpf filter!\n");
            perror("ioctl setting bpf filter");
            exit(1);
        }
    } else {
        var = DLT_IEEE802_11;
        if (ioctl(inf->fd, BIOCSDLT, &var)) {
            fprintf(stderr, "can't set bpf link layer type!\n");
            exit(1);
        }
        var = 1;
        if (ioctl(inf->fd, BIOCSHDRCMPLT, &var)) {
            fprintf(stderr, "can't tell bpf we are doing our own headers!\n");
            exit(1);
        }
        bpf_filter.bf_len = sizeof(allofit) / sizeof(struct bpf_insn);
        bpf_filter.bf_insns = allofit;
        if (ioctl(inf->fd, BIOCSETF, &bpf_filter)) {
            fprintf(stderr, "can't set bpf filter!\n");
            perror("ioctl setting bpf filter");
            exit(1);
        }
    }
    srv_add_input(srvctx, inf->fd, inf, bpf_in);
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
    unsigned long af;

    if (inf == NULL) {
        return;
    }
    memset(buf, 0, sizeof(buf));
    /*
     * add the loopback pseudo-header to indicate or pseudo-AF
     */
    af = AF_INET;
    memcpy(buf, &af, sizeof(unsigned long));
    frame = (struct ieee80211_mgmt_frame *)(buf + sizeof(unsigned long));
    frame->frame_control = ieee_order((IEEE802_11_FC_TYPE_MGMT << 2 | IEEE802_11_FC_STYPE_BEACON << 4));
    memcpy(frame->da, broadcast, ETH_ALEN);
    memcpy(frame->sa, inf->bssid, ETH_ALEN);
    memcpy(frame->bssid, inf->bssid, ETH_ALEN);

    /*
     * not a truely valid beacon but so what, this is a simulator and
     * all we really care about is the ssid
     */
    el = frame->beacon.variable;
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

/*
 * chan2freq()
 *      convert an 802.11 channel into a frequencey, stolen from ifconfig...
 */
static unsigned int
chan2freq(unsigned int chan)
{
    /*
     * "Kenneth, what is the frequency!!!????"
     *          - William Tager
     */
    if (chan == 14)
        return 2484;
    if (chan < 14)			/* 0-13 */
        return 2407 + chan*5;
    if (chan < 27)			/* 15-26 */
        return 2512 + ((chan-15)*20);
    return 5000 + (chan*5);
}

int
main (int argc, char **argv)
{
    int i, s, c, ret, mediaopt, band;
    unsigned int channel, freq;
    struct interface *inf;
    struct ifreq ifr;
    struct ieee80211req ireq;
    struct ifmediareq ifmreq;
    struct ieee80211req_chaninfo chans;
    struct sigaction act;
    char confdir[80], conffile[80], mesh_interface[10];
    char str[80], *ptr, *cruft;
    size_t needed;
    FILE *fp;
    int mib[6];
    struct if_msghdr *ifm;
    struct sockaddr_dl *sdl;

    strcpy(confdir, "/usr/local/config");
    for (;;) {
        c = getopt(argc, argv, "hI:b");
        if (c < 0) {
            break;
        }
        switch (c) {
            case 'I':
                snprintf(confdir, sizeof(confdir), optarg);
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
    channel = 6;
    mediaopt = MESHD_ADHOC;
    band = MESHD_11b;
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
            if (strncmp(str, "mediaopt", strlen("mediaopt")) == 0) {
                mediaopt = atoi(ptr);
            }
            if (strncmp(str, "channel", strlen("channel")) == 0) {
                channel = atoi(ptr);
            }
            if (strncmp(str, "band", strlen("band")) == 0) {
                if (strncmp(ptr, "11a", strlen("11a")) == 0) {
                    band = MESHD_11a;
                } else if (strncmp(ptr, "11b", strlen("11b")) == 0) {
                    band = MESHD_11b;
                } else if (strncmp(ptr, "11g", strlen("11g")) == 0) {
                    band = MESHD_11g;
                } else {
                    band = -1;
                }
            }
        }
    }

    if (TAILQ_EMPTY(&interfaces)) {
        fprintf(stderr, "%s: no interfaces defined!\n", argv[0]);
        add_interface("lo0");
    }
    printf("interfaces and MAC addresses:\n");
    TAILQ_FOREACH(inf, &interfaces, entry) {
        if (inf->is_loopback) {
            /*
             * no radio to configure but just set a timer for these
             * phony beacons
             */
            printf("\t%s: " MACSTR "\n", inf->ifname, MAC2STR(inf->bssid));
            (void)srv_add_timeout(srvctx, SRV_SEC(beacon), send_beacon, inf);
        } else {
            /*
             * not loopback, it's some radio so configure it!
             */
            if ((s = socket(PF_INET, SOCK_RAW, 0)) < 0) {
                fprintf(stderr, "unable to get raw socket to determine interface flags!\n");
                exit(1);
            }
            /*
             * get the link-layer address of the interface and make that
             * the radio's bssid
             */
            memset(&ifr, 0, sizeof(ifr));
            strlcpy(ifr.ifr_name, inf->ifname, IFNAMSIZ);
            if (ioctl(s, SIOCGIFINDEX, &ifr) < 0) {
                fprintf(stderr, "%s: cannot determine ifindex!\n", argv[0]);
                exit(1);
            }
            mib[0] = CTL_NET;
            mib[1] = PF_ROUTE;
            mib[2] = 0;
            mib[3] = 0;
            mib[4] = NET_RT_IFLIST;
            mib[5] = ifr.ifr_index;
            if (sysctl(mib, 6, NULL, &needed, NULL, 0) < 0) {
                fprintf(stderr, "%s: cannot determine size of info from sysctl!\n", argv[0]);
                exit(1);
            }
            if ((cruft = malloc(needed)) == NULL) {
                fprintf(stderr, "%s: cannot malloc space to retrieve sysctl info!\n", argv[0]);
                exit(1);
            }
            if (sysctl(mib, 6, cruft, &needed, NULL, 0) < 0) {
                free(cruft);
                fprintf(stderr, "%s: cannot obtain info from sysctl!\n", argv[0]);
                exit(1);
            }
            ifm = (struct if_msghdr *)cruft;
            if (ifm->ifm_type != RTM_IFINFO) {
                fprintf(stderr, "%s: unexpected result from sysctl, expected %d got %d\n",
                        argv[0], RTM_IFINFO, ifm->ifm_type);
                exit(1);
            }
            if (ifm->ifm_data.ifi_datalen == 0) {
                ifm->ifm_data.ifi_datalen = sizeof(struct if_data);
            }
            sdl = (struct sockaddr_dl *)((char *)ifm + sizeof(struct if_msghdr) - sizeof(struct if_data) + ifm->ifm_data.ifi_datalen);
            memcpy(inf->bssid, LLADDR(sdl), ETH_ALEN);
            free(cruft);

            memset(&ireq, 0, sizeof(struct ieee80211req));
            strlcpy(ireq.i_name, inf->ifname, IFNAMSIZ);
            ireq.i_type = IEEE80211_IOC_BSSID;
            ireq.i_len = ETH_ALEN;
            ireq.i_data = inf->bssid;
            if (ioctl(s, SIOCS80211, &ireq) < 0) {
                fprintf(stderr, "%s: unable to set bssid!\n", argv[0]);
                perror("ioctl setting bssid");
                exit(1);
            }
            printf("\t%s: " MACSTR "\n", inf->ifname, MAC2STR(inf->bssid));
            /*
             * enable RSN
             */
            memset(&ireq, 0, sizeof(struct ieee80211req));
            strlcpy(ireq.i_name, inf->ifname, IFNAMSIZ);
            ireq.i_type = IEEE80211_IOC_WPA;
            ireq.i_val = 2;
            if (ioctl(s, SIOCS80211, &ireq) < 0) {
                fprintf(stderr, "%s: unable to set RSN!\n", argv[0]);
                perror("ioctl setting RSN");
                exit(1);
            }
            /*
             * set the ssid
             */
            memset(&ireq, 0, sizeof(struct ieee80211req));
            strlcpy(ireq.i_name, inf->ifname, IFNAMSIZ);
            ireq.i_type = IEEE80211_IOC_SSID;
            ireq.i_data = mesh_ssid;
            ireq.i_len = strlen(mesh_ssid);

            if (ioctl(s, SIOCS80211, &ireq) < 0) {
                fprintf(stderr, "%s: unable to set SSID!\n", argv[0]);
                perror("ioctl");
                exit(1);
            }
            /*
             * set the media option
             */
            memset(&ifmreq, 0, sizeof(ifmreq));
            strlcpy(ifmreq.ifm_name, inf->ifname, IFNAMSIZ);
            if (ioctl(s, SIOCGIFMEDIA, &ifmreq) < 0) {
                fprintf(stderr, "%s: unable to get mediaopt!\n", argv[0]);
                exit(1);
            }
            switch (mediaopt) {
                case MESHD_STA:
                    ifmreq.ifm_current &= ~(IFM_IEEE80211_HOSTAP | IFM_IEEE80211_MONITOR | IFM_IEEE80211_ADHOC | IFM_IEEE80211_IBSS);
                    break;
                case MESHD_ADHOC:
                    ifmreq.ifm_current &= ~(IFM_IEEE80211_HOSTAP | IFM_IEEE80211_MONITOR | IFM_IEEE80211_IBSS);
                    ifmreq.ifm_current |= IFM_IEEE80211_ADHOC;
                    break;
                case MESHD_HOSTAP:
                    ifmreq.ifm_current &= ~(IFM_IEEE80211_MONITOR | IFM_IEEE80211_ADHOC | IFM_IEEE80211_IBSS);
                    ifmreq.ifm_current |= IFM_IEEE80211_HOSTAP;
                    break;
                case MESHD_MONITOR:
                    ifmreq.ifm_current &= ~(IFM_IEEE80211_HOSTAP | IFM_IEEE80211_ADHOC | IFM_IEEE80211_IBSS);
                    ifmreq.ifm_current |= IFM_IEEE80211_MONITOR;
                    break;
                case MESHD_IBSS:
                    ifmreq.ifm_current &= ~(IFM_IEEE80211_HOSTAP | IFM_IEEE80211_ADHOC | IFM_IEEE80211_MONITOR);
                    ifmreq.ifm_current |= IFM_IEEE80211_IBSS;
                    break;
            }
            ifmreq.ifm_current &= ~(IFM_IEEE80211_11A | IFM_IEEE80211_11B | IFM_IEEE80211_11G | IFM_IEEE80211_FH);
            switch (band) {
                case MESHD_11a:
                    ifmreq.ifm_current |= IFM_IEEE80211_11A;
                    break;
                case MESHD_11b:
                    ifmreq.ifm_current |= IFM_IEEE80211_11B;
                    break;
                case MESHD_11g:
                    ifmreq.ifm_current |= IFM_IEEE80211_11G;
                    break;
                default:
                    fprintf(stderr, "%s: unknown mode %d\n", argv[0], band);
                    exit(1);
            }

            if (ioctl(s, SIOCSIFMEDIA, &ifmreq) < 0) {
                fprintf(stderr, "%s: unable to set mediaopt!\n", argv[0]);
                perror("ioctl");
                exit(1);
            }

            /*
             * figure out what channels are allowable on this radio
             */
            memset(&ireq, 0, sizeof(ireq));
            strlcpy(ireq.i_name, inf->ifname, IFNAMSIZ);
            ireq.i_type = IEEE80211_IOC_CHANINFO;
            ireq.i_data = &chans;
            ireq.i_len = sizeof(chans);
            if (ioctl(s, SIOCG80211, &ireq) < 0) {
                fprintf(stderr, "%s: unable to get available channels!\n", argv[0]);
                exit(1);
            }

            freq = chan2freq(channel);
            for (i = 0; i < chans.ic_nchans; i++) {
                /*
                 * go through them all, ignore if not in the configured band 
                 */
                if (IEEE80211_IS_CHAN_A(&chans.ic_chans[i]) && (band != MESHD_11a)) {
                    continue;
                }
                if (!IEEE80211_IS_CHAN_A(&chans.ic_chans[i]) && (band == MESHD_11a)) {
                    continue;
                }
                if (freq == chans.ic_chans[i].ic_freq) {
                    break;
                }
            }
            if (i == chans.ic_nchans) {
                fprintf(stderr, "%s: invalid channel, %d, for band %s\n", argv[0], channel,
                        band == MESHD_11a ? "11a" : band == MESHD_11b ? "11b" : "11g");
                exit(1);
            }
            memset(&ireq, 0, sizeof(ireq));
            strlcpy(ireq.i_name, inf->ifname, IFNAMSIZ);
            ireq.i_type = IEEE80211_IOC_CHANNEL;
            ireq.i_val = channel;
            if (ioctl(s, SIOCS80211, &ireq) < 0) {
                fprintf(stderr, "%s: unable to set channel %d for band %s\n", argv[0], channel,
                        band == MESHD_11a ? "11a" : band == MESHD_11b ? "11b" : "11g");
                /* unfortunate, but is it fatal? Nah */
            }
            printf("setting to channel %d, frequency %d\n", channel, freq);
    
            /*
             * finally let's make sure the interface is up
             */
            if (ioctl(s, SIOCGIFFLAGS, &ifr) < 0) {
                fprintf(stderr, "%s: cannot get ifflags for %s\n", argv[0], inf->ifname);
                exit(1);
            }
            if ((ifr.ifr_flags & IFF_UP) == 0) {
                ifr.ifr_flags |= IFF_UP;
                if (ioctl(s, SIOCSIFFLAGS, &ifr) < 0) {
                    fprintf(stderr, "%s: can't set %s to UP!\n", argv[0], inf->ifname);
                }
            }
            close(s);
        }
    }

    /*
     * initialize SAE...
     */
    if (sae_initialize(mesh_ssid, confdir) < 0) {
        fprintf(stderr, "%s: cannot configure SAE, check config file!\n", argv[0]);
        exit(1);
    }

    /*
     * re-read the SAE config upon receipt of HUP
     */
    act.sa_handler = sae_read_config;
    sigaction(SIGHUP, &act, NULL);
    act.sa_handler = sae_dump_db;
    sigaction(SIGUSR1, &act, NULL);

    srv_main_loop(srvctx);

    exit(1);
}
