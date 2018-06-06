#!/bin/bash

CONFIG=/tmp/authsae.cfg

load_hwsim() {
    local nradios=$1
    sudo modprobe -r mac80211-hwsim &> /dev/null
    sudo modprobe mac80211-hwsim radios=$nradios
}

get_hwsim_radios() {
    local radios=""
    for dev in /sys/devices/virtual/mac80211_hwsim/*; do
        phy=$(basename $dev/ieee80211/*)
        radios="$radios $phy"
    done
    echo $radios
}

set_default_config() {
    cat > ${CONFIG} <<EOF
authsae:
{
 sae:
  {
    debug = 480;
    password = "thisisreallysecret";
    group = [19, 26, 21, 25, 20];
    blacklist = 5;
    thresh = 5;
    lifetime = 3600;
  };
 meshd:
  {
    meshid = "byteme";
    interface = "mesh0";
    band = "11g";
    channel = 1;
    htmode = "none";
    mcast-rate = 12;
  };
};
EOF
}

start_meshd() {
    local i=0
    read -a radios <<<"$@"

    IFACES=()
    LOGS=()

    sudo rfkill unblock all
    for radio in ${radios[@]}; do
        iface="smesh$i"
        log=/tmp/authsae-$i.log

        sudo iw phy $radio interface add $iface type mesh
        sudo ip link set $iface up

        MESHD=$(dirname $(realpath $0))/../build/linux/meshd-nl80211
        [ -x "${MESHD}" ] || err_exit "${MESHD} not found."

        let i=$((i+1))
        sudo rm -f $log
        sudo ${MESHD} -i $iface -c ${CONFIG} -o $log -B

        IFACES+=($iface)
        LOGS+=($log)
    done
    wait
}


err_exit() {
    echo $1
    exit 1
}
