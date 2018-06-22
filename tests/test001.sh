#!/bin/bash
#
# Minimal test established a peer link between two meshd instances over hwsim
#

. `dirname $0`/include.sh

[ $(uname) = "Linux" ] || err_exit "This test only runs on Linux"

cleanup() {
    sudo killall meshd-nl80211
    rm -fr "${TMP0}" "${TMP1}"
    exit 0
}

trap cleanup SIGINT

nradios=2
load_hwsim $nradios || err_exit "Failed to load mac80211-hwsim module."
set_default_configs $nradios
start_meshd $(get_hwsim_radios) || exit 2

wait_for_plinks $nradios

# Additional tests
TMP0=$(mktemp)
TMP1=$(mktemp)
LOG0=${LOGS[0]}
LOG1=${LOGS[1]}

# pmk match
cat ${LOG0} | grep pmk -A 2 > ${TMP0}
cat ${LOG1} | grep pmk -A 2 > ${TMP1}

diff ${TMP0} ${TMP1} || { echo "FAIL: pmk mismatch"; cat ${TMP0} ${TMP1}; exit 1; }

# mgtk exchange in both directions
cat ${LOG0} | grep ^mgtk -A 1 | tail -1 > ${TMP0}
cat ${LOG1} | grep "Received mgtk:" -A 1 | tail -1 > ${TMP1}

diff ${TMP0} ${TMP1} || { echo "FAIL: mgtk exchange failed"; cat ${TMP0} ${TMP1}; exit 1; }

cat ${LOG0} | grep "Received mgtk:" -A 1 | tail -1 > ${TMP0}
cat ${LOG1} | grep ^mgtk -A 1 | tail -1 > ${TMP1}

diff ${TMP0} ${TMP1} || { echo "FAIL: mgtk exchange failed"; cat ${TMP0} ${TMP1}; exit 1; }

echo PASS
cleanup
