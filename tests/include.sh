#!/bin/bash

cleanup() {
    sudo killall meshd-nl80211 2> /dev/null
    rm -fr "${TMP0}" "${TMP1}"
}

trap cleanup EXIT


wait_for_clean_start() {
    cleanup

    # Wait for no running meshd
    local TRIES=50

    for i in $(seq $TRIES); do
        if [ $(ps -ax | grep "meshd-nl80211" | grep -v "grep" | wc -l) -eq 0 ]; then 
            break
        fi
        sleep 1
    done

    [ $i -eq ${TRIES} ] && err_exit "Couldn't shut down meshd-nl80211"
}

load_hwsim() {
    local nradios=$1
    sudo modprobe -r mac80211-hwsim &> /dev/null
    sudo modprobe mac80211-hwsim radios=$nradios
    # enable beaconing in 5G band
    sudo iw reg set US
    # remove any leftover interfaces
    for i in /sys/devices/virtual/mac80211_hwsim/*/net/*; do sudo iw dev $(basename $i) del; done
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

start_mesh_iw() {
    local i=0
    read -a radios <<<"$@"

    IW_IFACES=()

    sudo rfkill unblock all
    for radio in ${radios[@]}; do
        iface="iwmesh$i"

        sudo iw phy $radio interface add $iface type mesh
        sudo ip link set $iface up
        # basic-rates must match that in set_sup_basic_rates()
        sudo iw dev $iface mesh join byteme freq 2412 NOHT basic-rates 1,2,5.5,11,6,12,24

        let i=$((i+1))
        IW_IFACES+=($iface)
    done
}

start_meshd() {
    local i=0
    read -a radios <<<"$@"

    IFACES=()
    LOGS=()

    LOGDIR=${LOGDIR:-/tmp}
    TESTNAME=$(basename $0)

    sudo rfkill unblock all
    for radio in ${radios[@]}; do
        conf=${CONFIGS[$i]}
        iface="smesh$i"
        log=$LOGDIR/$TESTNAME/authsae-$i.log
        mkdir -p $(dirname $log)

        if [ $(pgrep -f "meshd-nl80211 -i ${iface}" | wc -l) -eq 0 ]; then
            sudo iw phy $radio interface add $iface type mesh
            sudo ip link set $iface up

            MESHD=$(dirname $(realpath $0))/../build/linux/meshd-nl80211
            [ -x "${MESHD}" ] || err_exit "${MESHD} not found."

            let i=$((i+1))
            sudo rm -f $log
            sudo ${MESHD} -i $iface -c $conf -o $log -B 2>>$log
        fi

        IFACES+=($iface)
        LOGS+=($log)
    done
    wait
}

err_exit() {
    echo "FAIL: $1"
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
            sudo iw dev $iface station dump | grep -q ESTAB && break
            sleep 1
        done
        [ $j -eq ${TRIES} ] && err_exit "${iface} failed to establish a link"
    done
}
