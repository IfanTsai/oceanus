# oceanus [![GitHub](https://img.shields.io/github/license/IfanTsai/oceanus?style=flat)](https://github.com/IfanTsai/oceanus/blob/master/LICENSE)

oceanus is a userspace TCP/IP stack based on dpdk.

## Quick Start

### build DPDK

```bash
wget http://fast.dpdk.org/rel/dpdk-19.11.12.tar.xz
tar xvf dpdk-19.11.12.tar.xz
cd dpdk-stable-19.11.12
meson build
ninja -C build
cd build && sudo ninja install
```

### set DPDK lib path
```bash
sudo echo "/usr/local/lib/x86_64-linux-gnu" >> /etc/ld.so.conf
sudo ldconfig
```

### bind network interface
```bash
cd ..   # go back dpdk-stable-19.11.12
sudo modprobe uio_pci_generic
sudo insmod build/kernel/linux/igb_uio/igb_uio.ko
sudo insmod build/kernel/linux/kni/rte_kni.ko
sudo ifconfig eth0 down
sudo ./usertools/dpdk-devbind.py --bind=igb_uio eth0
```

### run oceanus
```bash
git clone git@github.com:IfanTsai/oceanus.git
cd oceanus/app && make -j4  # cd oceanus && make so && cd app && make
sudo make run
```
