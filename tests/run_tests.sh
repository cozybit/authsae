#!/bin/bash
#
# Run all the tests
#
if [ $UID -ne 0 ]; then
    exec sudo "$0" "$@"
fi

for t in $(realpath $(dirname $0)/test*.sh); do
    desc=$(sed -n 's/^# *//; 3p' $t)
    echo -n "$(basename $t) $desc..."
    $t || exit 1
done
