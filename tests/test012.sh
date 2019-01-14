#!/bin/bash
#
# max_plinks survives multiple leave/join
#
. `dirname $0`/include.sh

[ $(uname) = "Linux" ] || err_exit "This test only runs on Linux"

wait_for_clean_start

nradios=3
max_peers=4
cycles=10
load_hwsim $nradios || err_exit "Failed to load mac80211-hwsim module."
set_default_configs $nradios
# set peer link limit
for conf in ${CONFIGS[@]}; do
    sed -i 's/meshid/max-plinks='$max_peers';&/' $conf
done
start_meshd $(get_hwsim_radios) || err_exit "Failed to start meshd-nl80211"

wait_for_plinks $nradios

# leave and join the mesh a bunch of times from one radio.
# if accounting is correct, at the end all peers should
# have nradios - 1 peers (since that is < max_peers)
for i in $(seq $cycles); do
    restart_meshd ${IFACES[0]}
    wait_for_plinks $nradios

    for j in $(seq 0 $((nradios-1))); do
        iface=${IFACES[$j]}
        ct=$(sudo iw dev $iface station dump | grep ESTAB | wc -l)
        expected=$(( $nradios - 1 ))
        if [ $ct -ne $(( $nradios - 1)) ]; then
            err_exit "$iface had < $expected peers (iteration $i)"
        fi
    done
done

echo PASS
