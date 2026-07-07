#!/bin/bash
# 32 张网卡：2 个 pci-bridge，每个桥挂 16 张 virtio-net-pci
# MAC 编码: 52:54:00:00:0B:NN  (B=桥号 1/2, NN=槽位 0x0~0xf)
# tap 模式: 每张卡对应一个 tap 接口 tapX_Y, 关闭默认 ifup/ifdown 脚本
#   如需接入网桥/启用 vhost, 自行在 netdev 后追加: ,vhost=on 或 ,script=/etc/qemu-ifup,...

qemu-system-x86_64 \
    -enable-kvm -m 1024 \
    -drive file=vm.qcow2,if=virtio \
    \
    -device pci-bridge,id=pci_bridge1,bus=pci.0,chassis_nr=1,shpc=off \
    -device pci-bridge,id=pci_bridge2,bus=pci.0,chassis_nr=2,shpc=off \
    \
    -netdev tap,id=net1_0,ifname=tap1_0,script=no,downscript=no  -device virtio-net-pci,bus=pci_bridge1,addr=0x0,netdev=net1_0,mac=52:54:00:00:01:00 \
    -netdev tap,id=net1_1,ifname=tap1_1,script=no,downscript=no  -device virtio-net-pci,bus=pci_bridge1,addr=0x1,netdev=net1_1,mac=52:54:00:00:01:01 \
    -netdev tap,id=net1_2,ifname=tap1_2,script=no,downscript=no  -device virtio-net-pci,bus=pci_bridge1,addr=0x2,netdev=net1_2,mac=52:54:00:00:01:02 \
    -netdev tap,id=net1_3,ifname=tap1_3,script=no,downscript=no  -device virtio-net-pci,bus=pci_bridge1,addr=0x3,netdev=net1_3,mac=52:54:00:00:01:03 \
    -netdev tap,id=net1_4,ifname=tap1_4,script=no,downscript=no  -device virtio-net-pci,bus=pci_bridge1,addr=0x4,netdev=net1_4,mac=52:54:00:00:01:04 \
    -netdev tap,id=net1_5,ifname=tap1_5,script=no,downscript=no  -device virtio-net-pci,bus=pci_bridge1,addr=0x5,netdev=net1_5,mac=52:54:00:00:01:05 \
    -netdev tap,id=net1_6,ifname=tap1_6,script=no,downscript=no  -device virtio-net-pci,bus=pci_bridge1,addr=0x6,netdev=net1_6,mac=52:54:00:00:01:06 \
    -netdev tap,id=net1_7,ifname=tap1_7,script=no,downscript=no  -device virtio-net-pci,bus=pci_bridge1,addr=0x7,netdev=net1_7,mac=52:54:00:00:01:07 \
    -netdev tap,id=net1_8,ifname=tap1_8,script=no,downscript=no  -device virtio-net-pci,bus=pci_bridge1,addr=0x8,netdev=net1_8,mac=52:54:00:00:01:08 \
    -netdev tap,id=net1_9,ifname=tap1_9,script=no,downscript=no  -device virtio-net-pci,bus=pci_bridge1,addr=0x9,netdev=net1_9,mac=52:54:00:00:01:09 \
    -netdev tap,id=net1_a,ifname=tap1_a,script=no,downscript=no  -device virtio-net-pci,bus=pci_bridge1,addr=0xa,netdev=net1_a,mac=52:54:00:00:01:0a \
    -netdev tap,id=net1_b,ifname=tap1_b,script=no,downscript=no  -device virtio-net-pci,bus=pci_bridge1,addr=0xb,netdev=net1_b,mac=52:54:00:00:01:0b \
    -netdev tap,id=net1_c,ifname=tap1_c,script=no,downscript=no  -device virtio-net-pci,bus=pci_bridge1,addr=0xc,netdev=net1_c,mac=52:54:00:00:01:0c \
    -netdev tap,id=net1_d,ifname=tap1_d,script=no,downscript=no  -device virtio-net-pci,bus=pci_bridge1,addr=0xd,netdev=net1_d,mac=52:54:00:00:01:0d \
    -netdev tap,id=net1_e,ifname=tap1_e,script=no,downscript=no  -device virtio-net-pci,bus=pci_bridge1,addr=0xe,netdev=net1_e,mac=52:54:00:00:01:0e \
    -netdev tap,id=net1_f,ifname=tap1_f,script=no,downscript=no  -device virtio-net-pci,bus=pci_bridge1,addr=0xf,netdev=net1_f,mac=52:54:00:00:01:0f \
    \
    -netdev tap,id=net2_0,ifname=tap2_0,script=no,downscript=no  -device virtio-net-pci,bus=pci_bridge2,addr=0x0,netdev=net2_0,mac=52:54:00:00:02:00 \
    -netdev tap,id=net2_1,ifname=tap2_1,script=no,downscript=no  -device virtio-net-pci,bus=pci_bridge2,addr=0x1,netdev=net2_1,mac=52:54:00:00:02:01 \
    -netdev tap,id=net2_2,ifname=tap2_2,script=no,downscript=no  -device virtio-net-pci,bus=pci_bridge2,addr=0x2,netdev=net2_2,mac=52:54:00:00:02:02 \
    -netdev tap,id=net2_3,ifname=tap2_3,script=no,downscript=no  -device virtio-net-pci,bus=pci_bridge2,addr=0x3,netdev=net2_3,mac=52:54:00:00:02:03 \
    -netdev tap,id=net2_4,ifname=tap2_4,script=no,downscript=no  -device virtio-net-pci,bus=pci_bridge2,addr=0x4,netdev=net2_4,mac=52:54:00:00:02:04 \
    -netdev tap,id=net2_5,ifname=tap2_5,script=no,downscript=no  -device virtio-net-pci,bus=pci_bridge2,addr=0x5,netdev=net2_5,mac=52:54:00:00:02:05 \
    -netdev tap,id=net2_6,ifname=tap2_6,script=no,downscript=no  -device virtio-net-pci,bus=pci_bridge2,addr=0x6,netdev=net2_6,mac=52:54:00:00:02:06 \
    -netdev tap,id=net2_7,ifname=tap2_7,script=no,downscript=no  -device virtio-net-pci,bus=pci_bridge2,addr=0x7,netdev=net2_7,mac=52:54:00:00:02:07 \
    -netdev tap,id=net2_8,ifname=tap2_8,script=no,downscript=no  -device virtio-net-pci,bus=pci_bridge2,addr=0x8,netdev=net2_8,mac=52:54:00:00:02:08 \
    -netdev tap,id=net2_9,ifname=tap2_9,script=no,downscript=no  -device virtio-net-pci,bus=pci_bridge2,addr=0x9,netdev=net2_9,mac=52:54:00:00:02:09 \
    -netdev tap,id=net2_a,ifname=tap2_a,script=no,downscript=no  -device virtio-net-pci,bus=pci_bridge2,addr=0xa,netdev=net2_a,mac=52:54:00:00:02:0a \
    -netdev tap,id=net2_b,ifname=tap2_b,script=no,downscript=no  -device virtio-net-pci,bus=pci_bridge2,addr=0xb,netdev=net2_b,mac=52:54:00:00:02:0b \
    -netdev tap,id=net2_c,ifname=tap2_c,script=no,downscript=no  -device virtio-net-pci,bus=pci_bridge2,addr=0xc,netdev=net2_c,mac=52:54:00:00:02:0c \
    -netdev tap,id=net2_d,ifname=tap2_d,script=no,downscript=no  -device virtio-net-pci,bus=pci_bridge2,addr=0xd,netdev=net2_d,mac=52:54:00:00:02:0d \
    -netdev tap,id=net2_e,ifname=tap2_e,script=no,downscript=no  -device virtio-net-pci,bus=pci_bridge2,addr=0xe,netdev=net2_e,mac=52:54:00:00:02:0e \
    -netdev tap,id=net2_f,ifname=tap2_f,script=no,downscript=no  -device virtio-net-pci,bus=pci_bridge2,addr=0xf,netdev=net2_f,mac=52:54:00:00:02:0f
