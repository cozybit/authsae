/* Copyright (c) Facebook, Inc., 2018
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
 */

#include "aid.h"

#include <string.h>

// See 802.11-2016 section 9.4.1.8 AID field
#define MAX_AID 2007

#define DIV_ROUND_UP(x, y) ((x) + (y)-1) / (y)
#define BIT(x) (1UL << (x))

#define AID_BITMAP_LEN DIV_ROUND_UP(MAX_AID + 1, sizeof(uint32_t) * 8)

// MSB bits of the AID specify a word in the bitmap, LSB bits of the AID specify
// a bit in a word in the bitmap. This is the distance to shift to get the split
// between MSB and LSB.
#define AID_WORD_SHIFT (ffs(sizeof(uint32_t) * 8) - 1)

// These LSB bits specify a bit in a word in the bitmap
#define AID_WORD_MASK (BIT(AID_WORD_SHIFT) - 1)

static uint8_t aidmap_initialized;
static uint32_t aidmap[AID_BITMAP_LEN];

void init_aidmap() {
  // A value of 1 indicates "free"
  memset(aidmap, 0xff, sizeof(aidmap));

  // 0 is an invalid AID, mark it as "in use"
  aidmap[0] &= ~1;

  aidmap_initialized = 1;
}

void set_aid(uint16_t aid, uint8_t in_use) {
  // On first access we need to initialise the bitmap
  if (!aidmap_initialized) {
    init_aidmap();
  }

  // 0 is an invalid AID, we never modify it
  if (aid == 0) {
    return;
  }

  int word_index = aid >> AID_WORD_SHIFT;
  int bit = aid & AID_WORD_MASK;

  if (in_use) {
    // Claim by setting the bit to 0
    aidmap[word_index] &= ~BIT(bit);
  } else {
    // Release by setting the bit to 1
    aidmap[word_index] |= BIT(bit);
  }
}

void release_aid(uint16_t aid) {
  set_aid(aid, /* in_use */ 0);
}

uint16_t get_free_aid() {
  // On first access we need to initialise the bitmap
  if (!aidmap_initialized) {
    init_aidmap();
  }

  for (uint32_t word = 0; word < AID_BITMAP_LEN; word++) {
    int bit = ffs(aidmap[word]);
    if (bit) {
      uint16_t aid = word * sizeof(uint32_t) * 8 + (bit - 1);
      if (aid > MAX_AID) {
        return 0;
      }

      set_aid(aid, /* in_use */ 1);
      return aid;
    }
  }

  // Out of AIDs
  return 0;
}
