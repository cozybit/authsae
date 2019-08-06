#!/bin/bash
#
# node deletes station if other end is killed without close
#

. `dirname $0`/include.sh

[ $(uname) = "Linux" ] || err_exit "This test only runs on Linux"

wait_for_clean_start

nradios=2
load_hwsim $nradios || err_exit "Failed to load mac80211-hwsim module."

set_default_configs $nradios
# disable security
for conf in ${CONFIGS[@]}; do
    sed -i 's/meshid/is-secure=0;&/' $conf
done

start_meshd $(get_hwsim_radios) || err_exit "Failed to start meshd-nl80211"

wait_for_plinks $nradios

# Drop the link from radio 1 -> radio 2
restart_meshd smesh0

sleep 2

wait_for_plinks $nradios

# Make sure radio 2 deleted the station
for i in $LOGDIR/$TESTNAME/authsae-1.log; do
    grep -q "NL80211_DEL_STATION" $i || err_exit "no peer deletion in $i"
done

echo PASS
