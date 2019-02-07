#!/bin/bash
# run tests inside a VM, for CI.

# kvm passthrough isn't available in circle ci
QEMU=${QEMU:-qemu-system-x86_64}

KERNEL=testing-vm-kernel
ROOTFS=testing-vm-rootfs.img

# download a VM kernel from some random location on the internet
# the rootfs fstab mounts /dev/local with 9p in /local.  It should
# have iw and so on installed.
if [ ! -f $KERNEL ]; then
    curl -L -O "https://github.com/bcopeland/testing-vm/releases/download/v1.3/$KERNEL"
fi
if [ ! -f $ROOTFS ]; then
    curl -L -O "https://github.com/bcopeland/testing-vm/releases/download/v1.3/$ROOTFS.xz"
    xz -d $ROOTFS.xz
fi

export TESTOUT=$(/bin/pwd)/testout
export LOGDIR=$TESTOUT/logs

mkdir -p $LOGDIR
mkdir -p $TESTOUT/vmtests

$QEMU \
  -kernel $KERNEL \
  -drive file=$ROOTFS,format=raw,if=virtio \
  -fsdev local,security_model=none,id=fsdev-local,path=../.. \
  -device virtio-9p-pci,id=fs-local,fsdev=fsdev-local,mount_tag=/dev/local \
  -serial mon:stdio -nographic -vga none \
  -append "root=/dev/vda console=ttyS0" | tee $LOGDIR/testout.log

./testout-to-junit.sh $LOGDIR/testout.log > $TESTOUT/vmtests/results.xml
grep -q failure $TESTOUT/vmtests/results.xml && exit 1
exit 0
