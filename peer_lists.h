#ifndef _SAE_PEER_LISTS_H_
#define _SAE_PEER_LISTS_H_

#include <sys/queue.h>

#include "peers.h"

TAILQ_HEAD(blacklist, candidate) blacklist;
TAILQ_HEAD(peers, candidate) peers;

#define for_each_peer(peer) \
    TAILQ_FOREACH(peer, &peers, entry)

#endif /* _SAE_PEER_LISTS_H_ */
