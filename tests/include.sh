#!/bin/bash

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

set_default_configs() {
    CONFIGS=()
    for i in $(seq $1); do
        config=/tmp/authsae-$((i-1)).cfg
        cat > $config <<EOF
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
        CONFIGS+=($config)
    done
}

start_meshd() {
    local i=0
    read -a radios <<<"$@"

    IFACES=()
    LOGS=()

    sudo rfkill unblock all
    for radio in ${radios[@]}; do
        conf=${CONFIGS[$i]}
        iface="smesh$i"
        log=/tmp/authsae-$i.log

        sudo iw phy $radio interface add $iface type mesh
        sudo ip link set $iface up

        MESHD=$(dirname $(realpath $0))/../build/linux/meshd-nl80211
        [ -x "${MESHD}" ] || err_exit "${MESHD} not found."

        let i=$((i+1))
        sudo rm -f $log
        sudo ${MESHD} -i $iface -c $conf -o $log -B 2>>$log

        IFACES+=($iface)
        LOGS+=($log)
    done
    wait
}


err_exit() {
    echo $1
    exit 1
}

wait_for_plinks() {
    local nradios=$1

    # Wait for peer link establishment
    TRIES=50
    for i in $(seq 0 $((nradios-1))); do
        log=${LOGS[$i]}
        iface=${IFACES[$i]}
        for j in $(seq $TRIES); do
            grep established $log &> /dev/null && break
            echo -n .
            sleep 1
        done
        [ $j -eq ${TRIES} ] && err_exit "FAIL: $iface failed to establish a link"
    done
    echo
}
