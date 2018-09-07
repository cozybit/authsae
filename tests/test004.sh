#!/bin/bash
#
# Test peering with unencrypted mesh
#
. `dirname $0`/include.sh

[ $(uname) = "Linux" ] || err_exit "This test only runs on Linux"

cleanup() {
    sudo killall meshd-nl80211
    exit 0
}

trap cleanup SIGINT

nradios=2
load_hwsim $nradios || err_exit "Failed to load mac80211-hwsim module."

set_default_configs $nradios
# disable security
for conf in ${CONFIGS[@]}; do
    sed -i 's/meshid/is-secure=0;&/' $conf
done

start_meshd $(get_hwsim_radios) || exit 2

wait_for_plinks $nradios

echo PASS
cleanup
