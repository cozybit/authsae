#ifndef __CHAN_H
#define __CHAN_H

#include "ampe.h"

int ieee80211_channel_to_frequency(int chan, enum ieee80211_band band);

int ieee80211_frequency_to_channel(int freq);

enum channel_width ht_op_to_channel_width(
    struct ht_op_ie *ht_op,
    struct vht_op_ie *vht_op);
#endif /* __CHAN_H */
