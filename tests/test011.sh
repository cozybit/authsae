#!/bin/bash
#
# respects max_plinks configuration
#
. `dirname $0`/include.sh

[ $(uname) = "Linux" ] || err_exit "This test only runs on Linux"

wait_for_clean_start

nradios=8
max_peers=4
load_hwsim $nradios || err_exit "Failed to load mac80211-hwsim module."
set_default_configs $nradios
# set peer link limit
for conf in ${CONFIGS[@]}; do
    sed -i 's/meshid/max-plinks='$max_peers';&/' $conf
done
start_meshd $(get_hwsim_radios) || err_exit "Failed to start meshd-nl80211"

wait_for_plinks $nradios

# no radio should have more than max_peers peers
# and at least one radio should have max_peers peers
at_limit=0
for i in $(seq 0 $((nradios-1))); do
    iface=${IFACES[$i]}
    ct=$(sudo iw dev $iface station dump | grep ESTAB | wc -l)
    [ $ct -le $max_peers ] || err_exit "$iface had $ct > $num_peers peers"
    if [ $ct -eq $max_peers ]; then
      at_limit=1
    fi
done

[ $at_limit -eq 1 ] || err_exit "no interface at limit of $num_peers peers"

echo PASS
