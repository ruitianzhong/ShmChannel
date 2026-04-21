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

