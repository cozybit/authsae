#!/bin/bash
#
# HT40 works
#

. `dirname $0`/include.sh

[ $(uname) = "Linux" ] || err_exit "This test only runs on Linux"

wait_for_clean_start

nradios=4
load_hwsim $nradios || err_exit "Failed to load mac80211-hwsim module."
set_default_configs $nradios

# enable HT40+ on all radios
for conf in ${CONFIGS[@]}; do
    sed -i 's/htmode = "none"/htmode = "HT40-"/; s/11g/11a/; s/channel = 1/channel=153/' $conf
done

start_meshd $(get_hwsim_radios) || err_exit "Failed to start meshd-nl80211"
wait_for_plinks $nradios

echo PASS
