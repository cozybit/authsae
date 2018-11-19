#!/bin/bash
#
# both ends close peer link when one side deletes its peer
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

# Delete the peer from radio 1 -> radio 2
sudo iw dev smesh0 station del $(cat /sys/class/net/smesh1/address)

sleep 1

# Make sure it is no longer in ESTAB on either peer
for iface in smesh0 smesh1; do
    if sudo iw dev $iface station dump | grep -q ESTAB; then
        echo "Did not de-ESTAB after peer deletion"
        exit 3
    fi
done

echo PASS
cleanup
