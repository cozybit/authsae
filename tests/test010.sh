#!/bin/bash
#
# re-ESTABs if one side is restarted without closing
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

# Kill the meshd running on radio 1 without sending a close
pkill -9 -f "meshd-nl80211 -i smesh0"

# Remove the old interface
ip link set smesh0 down
iw smesh0 del

# Restart meshd there and make sure it works
start_meshd $(get_hwsim_radios) || err_exit "Failed to start meshd-nl80211"

wait_for_plinks $nradios

echo PASS
