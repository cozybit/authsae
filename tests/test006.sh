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

for i in $(seq 0 $((nradios-1))); do
    iface=${IFACES[$i]}
    echo "*** $iface ***"
    sudo iw dev $iface station dump | egrep 'Station|plink'
done

# one or both STAs should shut down the plink after 20 seconds
sleep 30

# if this repros then both stas will be in listen
for i in $(seq 0 $((nradios-1))); do
    iface=${IFACES[$i]}
    echo "*** $iface ***"
    sudo iw dev $iface station dump | egrep 'Station|plink'
done
