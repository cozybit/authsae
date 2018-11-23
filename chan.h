#ifndef __CHAN_H
#define __CHAN_H

#include "ampe.h"

int ieee80211_channel_to_frequency(int chan, enum ieee80211_band band);

int ieee80211_frequency_to_channel(int freq);

#endif /* __CHAN_H */
