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
#include <openssl/rand.h>
#include "service.h"
#include "common.h"
#include "sae.h"

struct interface {
    TAILQ_ENTRY(interface) entry;
    unsigned char ifname[IFNAMSIZ];
    unsigned char is_loopback;
    int fd;     /* BPF socket */
};
TAILQ_HEAD(bar, interface) interfaces;

service_context srvctx;
unsigned char mesh_ssid[33];

static void
bpf_in (int fd, void *data)
{
    struct interface *inf = (struct interface *)data;
    char el_id, el_len, ssid[33];
    unsigned char buf[2048], *ptr, *els;
    struct bpf_hdr *hdr;
    struct ieee80211_mgmt_frame *frame;
    unsigned short frame_control, grp, status, rc;
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
                            if ((el_len != 0) && (memcmp(ssid, mesh_ssid, strlen(ssid)) == 0)) {
                                printf("%s: beacon of %s from " MACSTR "\n", inf->ifname, ssid, MAC2STR(frame->sa));
                            }
                            break;
                        }
                        els += el_len;
                        left -= el_len;
                    }
                    break;
                case IEEE802_11_FC_STYPE_AUTH:
                    if (frame->authenticate.alg != SAE_AUTH_ALG) {
                        break;
                    }
                    switch (frame->authenticate.auth_seq) {
                        case SAE_AUTH_COMMIT:
                            printf("%s: %d COMMIT frame, " MACSTR " to " MACSTR " ", inf->ifname,
                                   framesize, MAC2STR(frame->sa), MAC2STR(frame->da));
                            status = ieee_order(frame->authenticate.status);
                            grp = ieee_order(*((unsigned short *)(frame->authenticate.variable)));
                            switch (status) {
                                case WLAN_STATUS_ANTI_CLOGGING_TOKEN_NEEDED:
                                    printf("rejecting due to no token\n");
                                    break;
                                case WLAN_STATUS_NOT_SUPPORTED_GROUP:
                                    printf("rejecting due to unsupported group %d\n", grp);
                                    break;
                                case 0:
                                    printf("offering group %d\n", grp);
                                    break;
                                default:
                                    printf("unknown status %d!!!\n", status);
                            }
                            break;
                        case SAE_AUTH_CONFIRM:
                            rc = ieee_order(*((unsigned short *)(frame->authenticate.variable)));
                            printf("%s: CONFIRM frame, " MACSTR " to " MACSTR ", rc = %d\n", 
                                   inf->ifname, MAC2STR(frame->sa), MAC2STR(frame->da), rc);
                            break;
                        default:
                            printf("%s: unknown frame (seq = %d), " MACSTR " to " MACSTR "\n", 
                                   inf->ifname, frame->authenticate.auth_seq, 
                                   MAC2STR(frame->sa), MAC2STR(frame->da));
                            break;
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
    if (inf->is_loopback) {
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

int
main (int argc, char **argv)
{
    int c, ret;
    struct interface *inf;
    char confdir[80], conffile[80];
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

    /*
     * put random cruft into the ssid field so if this field is not configured
     * then we won't print out the SSID.
     */
    RAND_pseudo_bytes(mesh_ssid, sizeof(mesh_ssid));
    snprintf(conffile, sizeof(conffile), "%s/mon.conf", confdir);
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
        }
    }

    if (TAILQ_EMPTY(&interfaces)) {
        fprintf(stderr, "%s: no interfaces defined!\n", argv[0]);
    } else {
        printf("listening on: ");
        TAILQ_FOREACH(inf, &interfaces, entry) {
            printf("%s ", inf->ifname);
        }
        printf("\n");
        srv_main_loop(srvctx);
    }
    exit(1);
}
