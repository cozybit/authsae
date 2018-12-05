#!/bin/bash
#
# VHT80 works
#

. `dirname $0`/include.sh

[ $(uname) = "Linux" ] || err_exit "This test only runs on Linux"

wait_for_clean_start

vht_configs=(
  'channel_width="80"; freq=5745; center_freq1=5775; center_freq2=0;'
  'channel_width="80+80"; freq=5745; center_freq1=5775; center_freq2=5210;'
)

nradios=4
for cfg in "${vht_configs[@]}"; do
    wait_for_clean_start

    load_hwsim $nradios || err_exit "Failed to load mac80211-hwsim module."
    set_default_configs $nradios

    # enable VHT on all radios
    for conf in ${CONFIGS[@]}; do
        sed -i 's/channel.*/'"$cfg"'/; s/htmode.*//; s/11g/11a/' $conf
    done

    start_meshd $(get_hwsim_radios) || err_exit "Failed to start meshd-nl80211"
    wait_for_plinks $nradios
done

echo PASS
