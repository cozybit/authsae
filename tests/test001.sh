#!/bin/bash
#
# establishes an encrypted peer link
#

. `dirname $0`/include.sh

[ $(uname) = "Linux" ] || err_exit "This test only runs on Linux"

wait_for_clean_start

nradios=2
load_hwsim $nradios || err_exit "Failed to load mac80211-hwsim module."
set_default_configs $nradios
start_meshd $(get_hwsim_radios) || err_exit "Failed to start meshd-nl80211"

wait_for_plinks $nradios

# Additional tests
TMP0=$(mktemp)
TMP1=$(mktemp)
LOG0=${LOGS[0]}
LOG1=${LOGS[1]}

# pmk match
cat ${LOG0} | grep pmk -A 2 > ${TMP0}
cat ${LOG1} | grep pmk -A 2 > ${TMP1}

diff ${TMP0} ${TMP1} || { echo "pmk mismatch"; cat ${TMP0} ${TMP1}; err_exit "pmk mismatch"; }

# mgtk exchange in both directions
cat ${LOG0} | grep ^mgtk -A 1 | tail -1 > ${TMP0}
cat ${LOG1} | grep "Received mgtk:" -A 1 | tail -1 > ${TMP1}

diff ${TMP0} ${TMP1} || { echo "mgtk mismatch"; cat ${TMP0} ${TMP1}; err_exit "mgtk exchange failed"; }

cat ${LOG0} | grep "Received mgtk:" -A 1 | tail -1 > ${TMP0}
cat ${LOG1} | grep ^mgtk -A 1 | tail -1 > ${TMP1}

diff ${TMP0} ${TMP1} || { echo "mgtk mismatch"; cat ${TMP0} ${TMP1}; err_exit "mgtk exchange failed"; }

echo PASS
