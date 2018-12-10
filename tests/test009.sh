#!/bin/bash
#
# VHT80 mesh creates VHT STAs
#

. `dirname $0`/include.sh

[ $(uname) = "Linux" ] || err_exit "This test only runs on Linux"

wait_for_clean_start

cfg='channel_width="80"; freq=5745; center_freq1=5775; center_freq2=0;'

nradios=4
load_hwsim $nradios || err_exit "Failed to load mac80211-hwsim module."
set_default_configs $nradios

# enable VHT on all radios, disable auto plinks in half of them
ctr=0
for conf in ${CONFIGS[@]}; do
    sed -i 's/channel.*/'"$cfg"'/; s/htmode.*//; s/11g/11a/' $conf
    if [ $(($ctr & 1)) -eq 0 ]; then
       sed -i 's/meshid/auto_open_plinks=0;&/' $conf
    fi
    let ctr=$(($ctr+1))
done

start_meshd $(get_hwsim_radios) || err_exit "Failed to start meshd-nl80211"
wait_for_plinks $nradios

grep -E -q "changing ht protection mode to: [^0]" $LOGDIR/$TESTNAME/authsae*.log && \
   err_exit "set protection for NON-HT STAs"

grep -q "new unauthed HT sta" $LOGDIR/$TESTNAME/authsae*.log && \
   err_exit "incorrectly created HT STAs"

grep -q "new unauthed VHT sta" $LOGDIR/$TESTNAME/authsae*.log || \
   err_exit "did not create VHT STAs"

echo PASS
