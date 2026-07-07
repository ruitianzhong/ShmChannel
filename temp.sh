#!/bin/bash
# 32 张网卡：2 个 pci-bridge，每个桥挂 16 张 virtio-net-pci
# MAC 编码: 52:54:00:00:0B:NN  (B=桥号 1/2, NN=槽位 0x0~0xf)

qemu-system-x86_64 \
    -enable-kvm -m 1024 \
    -drive file=vm.qcow2,if=virtio \
    \
    -device pci-bridge,id=pci_bridge1,bus=pci.0,chassis_nr=1,shpc=off \
    -device pci-bridge,id=pci_bridge2,bus=pci.0,chassis_nr=2,shpc=off \
    \
    -netdev user,id=net1_0  -device virtio-net-pci,bus=pci_bridge1,addr=0x0,netdev=net1_0,mac=52:54:00:00:01:00 \
    -netdev user,id=net1_1  -device virtio-net-pci,bus=pci_bridge1,addr=0x1,netdev=net1_1,mac=52:54:00:00:01:01 \
    -netdev user,id=net1_2  -device virtio-net-pci,bus=pci_bridge1,addr=0x2,netdev=net1_2,mac=52:54:00:00:01:02 \
    -netdev user,id=net1_3  -device virtio-net-pci,bus=pci_bridge1,addr=0x3,netdev=net1_3,mac=52:54:00:00:01:03 \
    -netdev user,id=net1_4  -device virtio-net-pci,bus=pci_bridge1,addr=0x4,netdev=net1_4,mac=52:54:00:00:01:04 \
    -netdev user,id=net1_5  -device virtio-net-pci,bus=pci_bridge1,addr=0x5,netdev=net1_5,mac=52:54:00:00:01:05 \
    -netdev user,id=net1_6  -device virtio-net-pci,bus=pci_bridge1,addr=0x6,netdev=net1_6,mac=52:54:00:00:01:06 \
    -netdev user,id=net1_7  -device virtio-net-pci,bus=pci_bridge1,addr=0x7,netdev=net1_7,mac=52:54:00:00:01:07 \
    -netdev user,id=net1_8  -device virtio-net-pci,bus=pci_bridge1,addr=0x8,netdev=net1_8,mac=52:54:00:00:01:08 \
    -netdev user,id=net1_9  -device virtio-net-pci,bus=pci_bridge1,addr=0x9,netdev=net1_9,mac=52:54:00:00:01:09 \
    -netdev user,id=net1_a  -device virtio-net-pci,bus=pci_bridge1,addr=0xa,netdev=net1_a,mac=52:54:00:00:01:0a \
    -netdev user,id=net1_b  -device virtio-net-pci,bus=pci_bridge1,addr=0xb,netdev=net1_b,mac=52:54:00:00:01:0b \
    -netdev user,id=net1_c  -device virtio-net-pci,bus=pci_bridge1,addr=0xc,netdev=net1_c,mac=52:54:00:00:01:0c \
    -netdev user,id=net1_d  -device virtio-net-pci,bus=pci_bridge1,addr=0xd,netdev=net1_d,mac=52:54:00:00:01:0d \
    -netdev user,id=net1_e  -device virtio-net-pci,bus=pci_bridge1,addr=0xe,netdev=net1_e,mac=52:54:00:00:01:0e \
    -netdev user,id=net1_f  -device virtio-net-pci,bus=pci_bridge1,addr=0xf,netdev=net1_f,mac=52:54:00:00:01:0f \
    \
    -netdev user,id=net2_0  -device virtio-net-pci,bus=pci_bridge2,addr=0x0,netdev=net2_0,mac=52:54:00:00:02:00 \
    -netdev user,id=net2_1  -device virtio-net-pci,bus=pci_bridge2,addr=0x1,netdev=net2_1,mac=52:54:00:00:02:01 \
    -netdev user,id=net2_2  -device virtio-net-pci,bus=pci_bridge2,addr=0x2,netdev=net2_2,mac=52:54:00:00:02:02 \
    -netdev user,id=net2_3  -device virtio-net-pci,bus=pci_bridge2,addr=0x3,netdev=net2_3,mac=52:54:00:00:02:03 \
    -netdev user,id=net2_4  -device virtio-net-pci,bus=pci_bridge2,addr=0x4,netdev=net2_4,mac=52:54:00:00:02:04 \
    -netdev user,id=net2_5  -device virtio-net-pci,bus=pci_bridge2,addr=0x5,netdev=net2_5,mac=52:54:00:00:02:05 \
    -netdev user,id=net2_6  -device virtio-net-pci,bus=pci_bridge2,addr=0x6,netdev=net2_6,mac=52:54:00:00:02:06 \
    -netdev user,id=net2_7  -device virtio-net-pci,bus=pci_bridge2,addr=0x7,netdev=net2_7,mac=52:54:00:00:02:07 \
    -netdev user,id=net2_8  -device virtio-net-pci,bus=pci_bridge2,addr=0x8,netdev=net2_8,mac=52:54:00:00:02:08 \
    -netdev user,id=net2_9  -device virtio-net-pci,bus=pci_bridge2,addr=0x9,netdev=net2_9,mac=52:54:00:00:02:09 \
    -netdev user,id=net2_a  -device virtio-net-pci,bus=pci_bridge2,addr=0xa,netdev=net2_a,mac=52:54:00:00:02:0a \
    -netdev user,id=net2_b  -device virtio-net-pci,bus=pci_bridge2,addr=0xb,netdev=net2_b,mac=52:54:00:00:02:0b \
    -netdev user,id=net2_c  -device virtio-net-pci,bus=pci_bridge2,addr=0xc,netdev=net2_c,mac=52:54:00:00:02:0c \
    -netdev user,id=net2_d  -device virtio-net-pci,bus=pci_bridge2,addr=0xd,netdev=net2_d,mac=52:54:00:00:02:0d \
    -netdev user,id=net2_e  -device virtio-net-pci,bus=pci_bridge2,addr=0xe,netdev=net2_e,mac=52:54:00:00:02:0e \
    -netdev user,id=net2_f  -device virtio-net-pci,bus=pci_bridge2,addr=0xf,netdev=net2_f,mac=52:54:00:00:02:0f
