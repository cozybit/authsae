#!/bin/bash
#
# user mpm interoperates with kernel mpm
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

read -a hwsim_radios <<<"$(get_hwsim_radios)"
start_meshd ${hwsim_radios[0]} || exit 1
start_mesh_iw ${hwsim_radios[1]} || exit 2
IFACES+=(${IW_IFACES[@]})

wait_for_plinks $nradios

echo PASS
cleanup
