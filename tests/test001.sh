#! /bin/bash
#
# Minimal test established a peer link between two meshd instances over hwsim
#

[ $(uname) = "Linux" ] || { echo "This test only runs on Linux"; exit 1; }

cleanup() {
    sudo killall meshd-nl80211
    rm -fr "${TMP1}" "${TMP2}"
}

trap cleanup SIGINT

sudo modprobe -r mac80211-hwsim &> /dev/null
sudo modprobe mac80211-hwsim radios=4 || { echo "Failed to load mac80211-hwsim module."; echo 1; }

sudo iw phy phy2 interface add mesh0 type mesh
sudo iw phy phy3 interface add mesh1 type mesh

sudo ip link set mesh0 up
sudo ip link set mesh1 up

MESHD=$(dirname $(realpath $0))/../build/linux/meshd-nl80211

[ -x "${MESHD}" ] || { echo "${MESHD}" not found.; exit 1; }

CONFIG=/tmp/authsae.cfg
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

LOG0=/tmp/authsae-0.log
LOG1=/tmp/authsae-1.log
sudo rm -f ${LOG0} ${LOG1}
sudo ${MESHD}   -i mesh0 -c ${CONFIG} -o ${LOG0} -B
sudo ${MESHD}   -i mesh1 -c ${CONFIG} -o ${LOG1} -B
wait

# Wait for peer link establishment
TRIES=50
for i in $(seq $TRIES)
do
    grep established ${LOG0} &> /dev/null && break
    echo -n .
    sleep 1
done

for j in $(seq $TRIES)
do
    grep established ${LOG1} &> /dev/null && break
    echo -n .
    sleep 1
done

[ $i -eq ${TRIES} ] && { echo "FAIL: mesh0 failed to establish a link"; exit 1; }
[ $j -eq ${TRIES} ] && { echo "FAIL: mesh1 failed to establish a link"; exit 1; }
echo -en "\r            \r"

# Additional tests
grep established ${LOG1} &> /dev/null || { echo "FAIL: mesh1 failed to establish a link"; exit 1; }

TMP0=$(mktemp)
TMP1=$(mktemp)

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
