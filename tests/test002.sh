#!/bin/bash
#
# exchanges igtk when pmf=1
#

. `dirname $0`/include.sh

[ $(uname) = "Linux" ] || err_exit "This test only runs on Linux"

wait_for_clean_start

nradios=2
load_hwsim $nradios || err_exit "Failed to load mac80211-hwsim module."

set_default_configs $nradios
# enable PMF
for conf in ${CONFIGS[@]}; do
    sed -i 's/meshid/pmf=1;&/' $conf
done

start_meshd $(get_hwsim_radios) || err_exit "Failed to start meshd-nl80211"

wait_for_plinks $nradios

# Additional tests
TMP0=$(mktemp)
TMP1=$(mktemp)
LOG0=${LOGS[0]}
LOG1=${LOGS[1]}

# pmk match
sed -e 's/.*] //' ${LOG0} | grep pmk -A 2 > ${TMP0}
sed -e 's/.*] //' ${LOG1} | grep pmk -A 2 > ${TMP1}

diff ${TMP0} ${TMP1} || { echo "pmk mismatch"; cat ${TMP0} ${TMP1}; err_exit "pmk mismatch"; }

# mgtk exchange in both directions
sed -e 's/.*] //' ${LOG0} | grep ^mgtk -A 1 | tail -1 > ${TMP0}
sed -e 's/.*] //' ${LOG1} | grep "Received mgtk:" -A 1 | tail -1 > ${TMP1}

diff ${TMP0} ${TMP1} || { echo "mgtk mismatch"; cat ${TMP0} ${TMP1}; err_exit "mgtk exchange failed"; }

sed -e 's/.*] //' ${LOG0} | grep "Received mgtk:" -A 1 | tail -1 > ${TMP0}
sed -e 's/.*] //' ${LOG1} | grep ^mgtk -A 1 | tail -1 > ${TMP1}

diff ${TMP0} ${TMP1} || { echo "mgtk mismatch"; cat ${TMP0} ${TMP1}; err_exit "mgtk exchange failed"; }

# igtk exchange in both directions
sed -e 's/.*] //' ${LOG0} | grep ^igtk -A 1 | tail -1 > ${TMP0}
sed -e 's/.*] //' ${LOG1} | grep "Received igtk:" -A 1 | tail -1 > ${TMP1}

[ -s $TMP0 ] || err_exit "No igtk received"

diff ${TMP0} ${TMP1} || { echo "igtk mismatch"; cat ${TMP0} ${TMP1}; err_exit "igtk exchange failed"; }

sed -e 's/.*] //' ${LOG0} | grep "Received igtk:" -A 1 | tail -1 > ${TMP0}
sed -e 's/.*] //' ${LOG1} | grep ^igtk -A 1 | tail -1 > ${TMP1}

diff ${TMP0} ${TMP1} || { echo "igtk mismatch"; cat ${TMP0} ${TMP1}; err_exit "igtk exchange failed"; }

echo PASS
