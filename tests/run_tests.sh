#!/bin/bash
#
# Run all the tests
#
for t in $(realpath $(dirname $0)/test*.sh); do
    echo "Running '$(basename $t)'..."
    $t
done

