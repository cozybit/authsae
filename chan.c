/* Channel utility routines.
 *
 * Copyright (c) 2007, 2008	Johannes Berg
 * Copyright (c) 2007		Andy Lutomirski
 * Copyright (c) 2007		Mike Kershaw
 * Copyright (c) 2008-2009		Luis R. Rodriguez
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "chan.h"
#include <stdlib.h>

int ieee80211_channel_to_frequency(int chan, enum ieee80211_band band) {
  /* see 802.11 17.3.8.3.2 and Annex J
   * there are overlapping channel numbers in 5GHz and 2GHz bands */
  if (chan <= 0)
    return 0; /* not supported */
  switch (band) {
    case IEEE80211_BAND_2GHZ:
      if (chan == 14)
        return 2484;
      else if (chan < 14)
        return 2407 + chan * 5;
      break;
    case IEEE80211_BAND_5GHZ:
      if (chan >= 182 && chan <= 196)
        return 4000 + chan * 5;
      else
        return 5000 + chan * 5;
      break;
    default:;
  }
  return 0; /* not supported */
}

int ieee80211_frequency_to_channel(int freq) {
  /* see 802.11-2007 17.3.8.3.2 and Annex J */
  if (freq == 2484)
    return 14;
  else if (freq < 2484)
    return (freq - 2407) / 5;
  else if (freq >= 4910 && freq <= 4980)
    return (freq - 4000) / 5;
  else if (freq <= 45000) /* DMG band lower limit */
    return (freq - 5000) / 5;
  else if (freq >= 58320 && freq <= 64800)
    return (freq - 56160) / 2160;
  else
    return 0;
}

enum channel_width ht_op_to_channel_width(
    struct ht_op_ie *ht_op,
    struct vht_op_ie *vht_op) {
  enum channel_width channel_width;

  if (!ht_op)
    return CHAN_WIDTH_20_NOHT;

  /* Determine width from VHT operation element, 802.11-2016 tables 9-252,3 */
  if (vht_op) {
    switch (vht_op->width) {
      case 3: /* deprecated */
        return CHAN_WIDTH_80P80;

      case 2: /* deprecated */
        return CHAN_WIDTH_160;

      case 1: /* 80-160; determine based on center freq settings */
        if (!vht_op->center_chan2) {
          return CHAN_WIDTH_80;
        }
        if (abs(vht_op->center_chan2 - vht_op->center_chan1) == 8) {
          return CHAN_WIDTH_160;
        }
        return CHAN_WIDTH_80P80;

      case 0: /* 20 or 40, handled below */
      default:
        break;
    }
  }

  switch (ht_op->ht_param & IEEE80211_HT_PARAM_CHA_SEC_OFFSET) {
    case IEEE80211_HT_PARAM_CHA_SEC_NONE:
      return CHAN_WIDTH_20;
      break;
    case IEEE80211_HT_PARAM_CHA_SEC_ABOVE:
    case IEEE80211_HT_PARAM_CHA_SEC_BELOW:
      return CHAN_WIDTH_40;
      break;
    default:
      channel_width = CHAN_WIDTH_20_NOHT;
      break;
  }

  return channel_width;
}
