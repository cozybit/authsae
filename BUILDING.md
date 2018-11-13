# Building `authsae`

`authsae` and its associated library `libsae` are easy to build on Linux. This page is intended as a quick reference on how to start building it from scratch on an Ubuntu VM, including which dependencies likely need to be installed.

1. Set up an Ubuntu VM (these instructions assume 18.04.1 LTS).
    1. `sudo apt install open-vm-tools-desktop` – gets you copy/paste stuff, at least for VMware
    1. `sudo apt install net-tools` – gets you `ifconfig`
    1. Reboot
1. Install all the things:
    ```
    sudo apt install gcc
    sudo apt install make
    sudo apt install cmake
    sudo apt install pkg-config
    sudo apt install libssl-dev
    sudo apt install libconfig-dev
    sudo apt install libnl-3-dev
    sudo apt install libnl-genl-3-dev
    ```
1. Build: `make all`
1. Test: `tests/run_tests.sh`
