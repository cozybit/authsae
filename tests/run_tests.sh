#!/bin/bash
#
# Run all the tests
#

# Make sure we're running as root
if [ $UID -ne 0 ]; then
    exec sudo "$0" "$@"
fi

# We require all calls to exit to use `err_exit`
grep -v "^#" $(realpath $(dirname $0)/test*.sh) | grep "exit" | grep -v "err_exit" && echo "FAIL: only 'err_exit' is supported to exit from a test, please fix" && exit 1

FAILED=0

# Run the tests
for t in $(realpath $(dirname $0)/test*.sh); do
    desc=$(sed -n 's/^# *//; 3p' $t)
    echo -n "$(basename $t) $desc..."
    $t || FAILED=1
done

echo
if [ $FAILED -eq 0 ]; then
    echo "All tests PASSED"
else
    echo "Some tests FAILED"
fi

exit $FAILED
