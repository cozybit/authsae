#!/bin/bash
#
# both ends close peer link when one side deletes its peer
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

# Delete the peer from radio 1 -> radio 2
sudo iw dev smesh0 station del $(cat /sys/class/net/smesh1/address)

sleep 1

# Make sure both peers sent close
for i in $LOGDIR/$TESTNAME/authsae*log; do
    grep -q "Sending plink action 3" $i || err_exit "no close frame in $i"
done

echo PASS
