#!/bin/bash
#
# mixed HT/non-HT neighbors can peer
#

. `dirname $0`/include.sh

[ $(uname) = "Linux" ] || err_exit "This test only runs on Linux"

wait_for_clean_start

nradios=4
load_hwsim $nradios || err_exit "Failed to load mac80211-hwsim module."
set_default_configs $nradios

# enable HT20 on all radios
for conf in ${CONFIGS[@]}; do
    sed -i 's/htmode = "none"/htmode = "HT20"/' $conf
done

start_meshd $(get_hwsim_radios) || err_exit "Failed to start meshd-nl80211"
wait_for_plinks $nradios

# introduce a non-HT sta to switch from no protection to mixed
sudo pkill -f meshd-nl80211.*${IFACES[0]}
sudo rm -f ${LOGS[0]}
sed -i 's/htmode = "HT20"/htmode = "none"/' ${CONFIGS[0]}
sudo ${MESHD} -i ${IFACES[0]} -c ${CONFIGS[0]} -o ${LOGS[0]} -B
wait_for_plinks $nradios

# make sure there is no 'nlerror 29' -- this can happen on kernels
# >= 4.8 and <= TBD.  If this fails it indicates HT oper switch is
# broken in the kernel.
grep "nlerror, cmd 29" /tmp/authsae*.log && err_exit "set meshconf failed"

echo PASS
