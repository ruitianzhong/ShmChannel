#!/bin/bash
qemu-system-x86_64 \
  -enable-kvm \
  -m 2G \
  -smp 2 \
  -nographic \
    -serial mon:stdio \
  -drive file=base.qcow2,format=qcow2,if=virtio \
  -object memory-backend-file,id=mem0,size=2G,mem-path=./mem.raw,share=on \
  -machine memory-backend=mem0 \
  -netdev tap,id=net0,ifname=tap0,script=no,downscript=no \
  -device virtio-net-pci,netdev=net0 \
  -qmp unix:./qmp-sock,server,nowait \
  -global monitor-event.disable=on \
  -device vhost-vsock-pci,id=vhost-vsock0,guest-cid=3


qemu-system-x86_64 \
  -enable-kvm \
  -m 2G \
  -smp 2 \
  -nographic \
    -serial mon:stdio \
  -drive file=vm2-fork.qcow2,format=qcow2,if=virtio \
  -object memory-backend-file,id=mem0,size=2G,mem-path=./mem.raw,share=off \
  -machine memory-backend=mem0 \
  -netdev tap,id=net0,ifname=tap0,script=no,downscript=no \
  -device virtio-net-pci,netdev=net0 \
  -S -incoming defer \
  -qmp unix:./qmp-restore-sock,server,nowait \
  -device vhost-vsock-pci,id=vhost-vsock0,guest-cid=4



  qemu-system-x86_64 \
-machine q35,accel=kvm \
-smp 4 \
-m 8G \
-cpu host \
# 系统盘自行替换成你的镜像
-drive file=/path/to/your-disk.qcow2,if=none,id=hd0 \
-device virtio-blk-pci,drive=hd0,bus=pcie.0,addr=0x0 \
-vga virtio \
-serial stdio \
-monitor telnet:127.0.0.1:5555,server,nowait \
# ====================== 30个PCIe根端口 ======================
-device pcie-root-port,bus=pcie.0,addr=0x10.0,port=1,chassis=1,multifunction=on \
-device pcie-root-port,bus=pcie.0,addr=0x10.1,port=2,chassis=2 \
-device pcie-root-port,bus=pcie.0,addr=0x10.2,port=3,chassis=3 \
-device pcie-root-port,bus=pcie.0,addr=0x10.3,port=4,chassis=4 \
-device pcie-root-port,bus=pcie.0,addr=0x10.4,port=5,chassis=5 \
-device pcie-root-port,bus=pcie.0,addr=0x10.5,port=6,chassis=6 \
-device pcie-root-port,bus=pcie.0,addr=0x10.6,port=7,chassis=7 \
-device pcie-root-port,bus=pcie.0,addr=0x10.7,port=8,chassis=8 \
-device pcie-root-port,bus=pcie.0,addr=0x11.0,port=9,chassis=9 \
-device pcie-root-port,bus=pcie.0,addr=0x11.1,port=10,chassis=10 \
-device pcie-root-port,bus=pcie.0,addr=0x11.2,port=11,chassis=11 \
-device pcie-root-port,bus=pcie.0,addr=0x11.3,port=12,chassis=12 \
-device pcie-root-port,bus=pcie.0,addr=0x11.4,port=13,chassis=13 \
-device pcie-root-port,bus=pcie.0,addr=0x11.5,port=14,chassis=14 \
-device pcie-root-port,bus=pcie.0,addr=0x11.6,port=15,chassis=15 \
-device pcie-root-port,bus=pcie.0,addr=0x11.7,port=16,chassis=16 \
-device pcie-root-port,bus=pcie.0,addr=0x12.0,port=17,chassis=17 \
-device pcie-root-port,bus=pcie.0,addr=0x12.1,port=18,chassis=18 \
-device pcie-root-port,bus=pcie.0,addr=0x12.2,port=19,chassis=19 \
-device pcie-root-port,bus=pcie.0,addr=0x12.3,port=20,chassis=20 \
-device pcie-root-port,bus=pcie.0,addr=0x12.4,port=21,chassis=21 \
-device pcie-root-port,bus=pcie.0,addr=0x12.5,port=22,chassis=22 \
-device pcie-root-port,bus=pcie.0,addr=0x12.6,port=23,chassis=23 \
-device pcie-root-port,bus=pcie.0,addr=0x12.7,port=24,chassis=24 \
-device pcie-root-port,bus=pcie.0,addr=0x13.0,port=25,chassis=25 \
-device pcie-root-port,bus=pcie.0,addr=0x13.1,port=26,chassis=26 \
-device pcie-root-port,bus=pcie.0,addr=0x13.2,port=27,chassis=27 \
-device pcie-root-port,bus=pcie.0,addr=0x13.3,port=28,chassis=28 \
-device pcie-root-port,bus=pcie.0,addr=0x13.4,port=29,chassis=29 \
-device pcie-root-port,bus=pcie.0,addr=0x13.5,port=30,chassis=30 \
# ====================== 网卡1 ======================
-netdev tap,ifname=tap0,id=net0,vhost=on \
-device virtio-net-pci,netdev=net0,bus=pcie.1,addr=0x0,mac=52:54:00:00:01:00,mq=4 \
# ====================== 网卡2 ======================
-netdev tap,ifname=tap1,id=net1,vhost=on \
-device virtio-net-pci,netdev=net1,bus=pcie.2,addr=0x0,mac=52:54:00:00:01:01,mq=4 \
# ====================== 网卡3 ======================
-netdev tap,ifname=tap2,id=net2,vhost=on \
-device virtio-net-pci,netdev=net2,bus=pcie.3,addr=0x0,mac=52:54:00:00:01:02,mq=4 \
# ====================== 网卡4 ======================
-netdev tap,ifname=tap3,id=net3,vhost=on \
-device virtio-net-pci,netdev=net3,bus=pcie.4,addr=0x0,mac=52:54:00:00:01:03,mq=4 \
# ====================== 网卡5 ======================
-netdev tap,ifname=tap4,id=net4,vhost=on \
-device virtio-net-pci,netdev=net4,bus=pcie.5,addr=0x0,mac=52:54:00:00:01:04,mq=4 \
# ====================== 网卡6 ======================
-netdev tap,ifname=tap5,id=net5,vhost=on \
-device virtio-net-pci,netdev=net5,bus=pcie.6,addr=0x0,mac=52:54:00:00:01:05,mq=4 \
# ====================== 网卡7 ======================
-netdev tap,ifname=tap6,id=net6,vhost=on \
-device virtio-net-pci,netdev=net6,bus=pcie.7,addr=0x0,mac=52:54:00:00:01:06,mq=4 \
# ====================== 网卡8 ======================
-netdev tap,ifname=tap7,id=net7,vhost=on \
-device virtio-net-pci,netdev=net7,bus=pcie.8,addr=0x0,mac=52:54:00:00:01:07,mq=4 \
# ====================== 网卡9 ======================
-netdev tap,ifname=tap8,id=net8,vhost=on \
-device virtio-net-pci,netdev=net8,bus=pcie.9,addr=0x0,mac=52:54:00:00:01:08,mq=4 \
# ====================== 网卡10 ======================
-netdev tap,ifname=tap9,id=net9,vhost=on \
-device virtio-net-pci,netdev=net9,bus=pcie.10,addr=0x0,mac=52:54:00:00:01:09,mq=4 \
# ====================== 网卡11 ======================
-netdev tap,ifname=tap10,id=net10,vhost=on \
-device virtio-net-pci,netdev=net10,bus=pcie.11,addr=0x0,mac=52:54:00:00:01:0a,mq=4 \
# ====================== 网卡12 ======================
-netdev tap,ifname=tap11,id=net11,vhost=on \
-device virtio-net-pci,netdev=net11,bus=pcie.12,addr=0x0,mac=52:54:00:00:01:0b,mq=4 \
# ====================== 网卡13 ======================
-netdev tap,ifname=tap12,id=net12,vhost=on \
-device virtio-net-pci,netdev=net12,bus=pcie.13,addr=0x0,mac=52:54:00:00:01:0c,mq=4 \
# ====================== 网卡14 ======================
-netdev tap,ifname=tap13,id=net13,vhost=on \
-device virtio-net-pci,netdev=net13,bus=pcie.14,addr=0x0,mac=52:54:00:00:01:0d,mq=4 \
# ====================== 网卡15 ======================
-netdev tap,ifname=tap14,id=net14,vhost=on \
-device virtio-net-pci,netdev=net14,bus=pcie.15,addr=0x0,mac=52:54:00:00:01:0e,mq=4 \
# ====================== 网卡16 ======================
-netdev tap,ifname=tap15,id=net15,vhost=on \
-device virtio-net-pci,netdev=net15,bus=pcie.16,addr=0x0,mac=52:54:00:00:01:0f,mq=4 \
# ====================== 网卡17 ======================
-netdev tap,ifname=tap16,id=net16,vhost=on \
-device virtio-net-pci,netdev=net16,bus=pcie.17,addr=0x0,mac=52:54:00:00:01:10,mq=4 \
# ====================== 网卡18 ======================
-netdev tap,ifname=tap17,id=net17,vhost=on \
-device virtio-net-pci,netdev=net17,bus=pcie.18,addr=0x0,mac=52:54:00:00:01:11,mq=4 \
# ====================== 网卡19 ======================
-netdev tap,ifname=tap18,id=net18,vhost=on \
-device virtio-net-pci,netdev=net18,bus=pcie.19,addr=0x0,mac=52:54:00:00:01:12,mq=4 \
# ====================== 网卡20 ======================
-netdev tap,ifname=tap19,id=net19,vhost=on \
-device virtio-net-pci,netdev=net19,bus=pcie.20,addr=0x0,mac=52:54:00:00:01:13,mq=4 \
# ====================== 网卡21 ======================
-netdev tap,ifname=tap20,id=net20,vhost=on \
-device virtio-net-pci,netdev=net20,bus=pcie.21,addr=0x0,mac=52:54:00:00:01:14,mq=4 \
# ====================== 网卡22 ======================
-netdev tap,ifname=tap21,id=net21,vhost=on \
-device virtio-net-pci,netdev=net21,bus=pcie.22,addr=0x0,mac=52:54:00:00:01:15,mq=4 \
# ====================== 网卡23 ======================
-netdev tap,ifname=tap22,id=net22,vhost=on \
-device virtio-net-pci,netdev=net22,bus=pcie.23,addr=0x0,mac=52:54:00:00:01:16,mq=4 \
# ====================== 网卡24 ======================
-netdev tap,ifname=tap23,id=net23,vhost=on \
-device virtio-net-pci,netdev=net23,bus=pcie.24,addr=0x0,mac=52:54:00:00:01:17,mq=4 \
# ====================== 网卡25 ======================
-netdev tap,ifname=tap24,id=net24,vhost=on \
-device virtio-net-pci,netdev=net24,bus=pcie.25,addr=0x0,mac=52:54:00:00:01:18,mq=4 \
# ====================== 网卡26 ======================
-netdev tap,ifname=tap25,id=net25,vhost=on \
-device virtio-net-pci,netdev=net25,bus=pcie.26,addr=0x0,mac=52:54:00:00:01:19,mq=4 \
# ====================== 网卡27 ======================
-netdev tap,ifname=tap26,id=net26,vhost=on \
-device virtio-net-pci,netdev=net26,bus=pcie.27,addr=0x0,mac=52:54:00:00:01:1a,mq=4 \
# ====================== 网卡28 ======================
-netdev tap,ifname=tap27,id=net27,vhost=on \
-device virtio-net-pci,netdev=net27,bus=pcie.28,addr=0x0,mac=52:54:00:00:01:1b,mq=4 \
# ====================== 网卡29 ======================
-netdev tap,ifname=tap28,id=net28,vhost=on \
-device virtio-net-pci,netdev=net28,bus=pcie.29,addr=0x0,mac=52:54:00:00:01:1c,mq=4 \
# ====================== 网卡30 ======================
-netdev tap,ifname=tap29,id=net29,vhost=on \
-device virtio-net-pci,netdev=net29,bus=pcie.30,addr=0x0,mac=52:54:00:00:01:1d,mq=4


qemu-system-x86_64 \
    -enable-kvm \
    -m 2048 \
    -smp 4 \
    -drive file=vm.qcow2,if=virtio \
    -netdev tap,id=net0,ifname=tap0,script=no,downscript=no \
    -device virtio-net-pci,netdev=net0,mac=52:54:00:00:00:01 \
    -device pci-bridge,id=pci_bridge1,bus=pci.0,chassis_nr=1,shpc=off \
    -netdev tap,id=net1,ifname=tap1,script=no,downscript=no \
    -device virtio-net-pci,bus=pci_bridge1,addr=0x0,netdev=net1,mac=52:54:00:00:01:01

    qemu-system-x86_64 \
    -enable-kvm -m 1024 \
    -drive file=vm.qcow2,if=virtio \
    \
    # 定义2个PCI桥
    -device pci-bridge,id=pci_bridge1,bus=pci.0,chassis_nr=1,shpc=off \
    -device pci-bridge,id=pci_bridge2,bus=pci.0,chassis_nr=2,shpc=off \
    \
    # ========== 桥1：前16张网卡 net0 ~ net15 (addr 0x0 ~ 0xf) ==========
    -netdev user,id=net0,hostfwd=tcp::2222-:22 \
    -device virtio-net-pci,bus=pci_bridge1,addr=0x0,netdev=net0,mac=52:54:00:00:00:01 \
    \
    -netdev user,id=net1 \
    -device virtio-net-pci,bus=pci_bridge1,addr=0x1,netdev=net1,mac=52:54:00:00:00:02 \
    \
    -netdev user,id=net2 \
    -device virtio-net-pci,bus=pci_bridge1,addr=0x2,netdev=net2,mac=52:54:00:00:00:03 \
    \
    -netdev user,id=net3 \
    -device virtio-net-pci,bus=pci_bridge1,addr=0x3,netdev=net3,mac=52:54:00:00:00:04 \
    \
    -netdev user,id=net4 \
    -device virtio-net-pci,bus=pci_bridge1,addr=0x4,netdev=net4,mac=52:54:00:00:00:05 \
    \
    -netdev user,id=net5 \
    -device virtio-net-pci,bus=pci_bridge1,addr=0x5,netdev=net5,mac=52:54:00:00:00:06 \
    \
    -netdev user,id=net6 \
    -device virtio-net-pci,bus=pci_bridge1,addr=0x6,netdev=net6,mac=52:54:00:00:00:07 \
    \
    -netdev user,id=net7 \
    -device virtio-net-pci,bus=pci_bridge1,addr=0x7,netdev=net7,mac=52:54:00:00:00:08 \
    \
    -netdev user,id=net8 \
    -device virtio-net-pci,bus=pci_bridge1,addr=0x8,netdev=net8,mac=52:54:00:00:00:09 \
    \
    -netdev user,id=net9 \
    -device virtio-net-pci,bus=pci_bridge1,addr=0x9,netdev=net9,mac=52:54:00:00:00:0a \
    \
    -netdev user,id=net10 \
    -device virtio-net-pci,bus=pci_bridge1,addr=0xa,netdev=net10,mac=52:54:00:00:00:0b \
    \
    -netdev user,id=net11 \
    -device virtio-net-pci,bus=pci_bridge1,addr=0xb,netdev=net11,mac=52:54:00:00:00:0c \
    \
    -netdev user,id=net12 \
    -device virtio-net-pci,bus=pci_bridge1,addr=0xc,netdev=net12,mac=52:54:00:00:00:0d \
    \
    -netdev user,id=net13 \
    -device virtio-net-pci,bus=pci_bridge1,addr=0xd,netdev=net13,mac=52:54:00:00:00:0e \
    \
    -netdev user,id=net14 \
    -device virtio-net-pci,bus=pci_bridge1,addr=0xe,netdev=net14,mac=52:54:00:00:00:0f \
    \
    -netdev user,id=net15 \
    -device virtio-net-pci,bus=pci_bridge1,addr=0xf,netdev=net15,mac=52:54:00:00:00:10 \
    \
    # ========== 桥2：后16张网卡 net16 ~ net31 (addr 0x0 ~ 0xf) ==========
    -netdev user,id=net16 \
    -device virtio-net-pci,bus=pci_bridge2,addr=0x0,netdev=net16,mac=52:54:00:00:01:01 \
    \
    -netdev user,id=net17 \
    -device virtio-net-pci,bus=pci_bridge2,addr=0x1,netdev=net17,mac=52:54:00:00:01:02 \
    \
    -netdev user,id=net18 \
    -device virtio-net-pci,bus=pci_bridge2,addr=0x2,netdev=net18,mac=52:54:00:00:01:03 \
    \
    -netdev user,id=net19 \
    -device virtio-net-pci,bus=pci_bridge2,addr=0x3,netdev=net19,mac=52:54:00:00:01:04 \
    \
    -netdev user,id=net20 \
    -device virtio-net-pci,bus=pci_bridge2,addr=0x4,netdev=net20,mac=52:54:00:00:01:05 \
    \
    -netdev user,id=net21 \
    -device virtio-net-pci,bus=pci_bridge2,addr=0x5,netdev=net21,mac=52:54:00:00:01:06 \
    \
    -netdev user,id=net22 \
    -device virtio-net-pci,bus=pci_bridge2,addr=0x6,netdev=net22,mac=52:54:00:00:01:07 \
    \
    -netdev user,id=net23 \
    -device virtio-net-pci,bus=pci_bridge2,addr=0x7,netdev=net23,mac=52:54:00:00:01:08 \
    \
    -netdev user,id=net24 \
    -device virtio-net-pci,bus=pci_bridge2,addr=0x8,netdev=net24,mac=52:54:00:00:01:09 \
    \
    -netdev user,id=net25 \
    -device virtio-net-pci,bus=pci_bridge2,addr=0x9,netdev=net25,mac=52:54:00:00:01:0a \
    \
    -netdev user,id=net26 \
    -device virtio-net-pci,bus=pci_bridge2,addr=0xa,netdev=net26,mac=52:54:00:00:01:0b \
    \
    -netdev user,id=net27 \
    -device virtio-net-pci,bus=pci_bridge2,addr=0xb,netdev=net27,mac=52:54:00:00:01:0c \
    \
    -netdev user,id=net28 \
    -device virtio-net-pci,bus=pci_bridge2,addr=0xc,netdev=net28,mac=52:54:00:00:01:0d \
    \
    -netdev user,id=net29 \
    -device virtio-net-pci,bus=pci_bridge2,addr=0xd,netdev=net29,mac=52:54:00:00:01:0e \
    \
    -netdev user,id=net30 \
    -device virtio-net-pci,bus=pci_bridge2,addr=0xe,netdev=net30,mac=52:54:00:00:01:0f \
    \
    -netdev user,id=net31 \
    -device virtio-net-pci,bus=pci_bridge2,addr=0xf,netdev=net31,mac=52:54:00:00:01:10

