
sudo systemctl mask systemd-networkd-wait-online
sudo dhclient ens3


qemu-img create -f qcow2 -b jammy-server-cloudimg-amd64.img -F qcow2 vm1.qcow2
qemu-img create -f qcow2 -b jammy-server-cloudimg-amd64.img -F qcow2 vm2.qcow2
qemu-img create -f qcow2 -b jammy-server-cloudimg-amd64.img -F qcow2 vm3.qcow2


sudo ip tuntap add dev tap0 mode tap 
sudo ip link set tap0 up

sudo ip tuntap add dev tap1 mode tap
sudo ip link set tap1 up 

sudo ip tuntap add dev tap2 mode tap
sudo ip link set tap2 up 

sudo ip addr add 192.168.0.1/30 dev tap0 
sudo ip addr add 192.168.0.2/30 dev ens3
ip link set dev ens3 up
sudo ip route add default via  192.168.0.1 dev ens3

sudo ip addr add 192.168.0.5/30 dev tap1 
sudo ip addr add 192.168.0.6/30 dev ens3


sudo ip addr add 192.168.0.9/30 dev tap2
sudo ip addr add 192.168.0.10/30 dev ens3
sudo ip link set ens3 up


ip link set dev ens3 up
sudo ip route add default via  192.168.0.5 dev ens3
ip link set dev ens3 up

sudo sysctl -w net.ipv4.conf.all.forwarding=1


# ============ 启动 VM1 (网卡 tap0) ============
# host 侧 tap0 已配置 192.168.0.1/30, VM1 内应配 192.168.0.2
sudo qemu-system-x86_64 \
  -enable-kvm -m 1024 -smp 2 -cpu host \
  -drive file=vm1.qcow2,format=qcow2,if=virtio \
  -netdev tap,id=n0,ifname=tap0,script=no,downscript=no \
  -device virtio-net-pci,netdev=n0,mac=52:54:00:00:00:01 \
  -nographic \
  -qmp unix:/tmp/vm1.sock,server,nowait

# ============ 启动 VM2 (网卡 tap1) ============
# host 侧 tap1 已配置 192.168.0.5/30, VM2 内应配 192.168.0.6
sudo qemu-system-x86_64 \
  -enable-kvm -m 1024 -smp 2 -cpu host \
  -drive file=vm2.qcow2,format=qcow2,if=virtio \
  -netdev tap,id=n0,ifname=tap1,script=no,downscript=no \
  -device virtio-net-pci,netdev=n0,mac=52:54:00:00:00:02 \
  -nographic

sudo qemu-system-x86_64 \
  -enable-kvm -m 1024 -smp 2 -cpu host \
  -drive file=vm3.qcow2,format=qcow2,if=virtio \
  -netdev tap,id=n0,ifname=tap2,script=no,downscript=no \
  -device virtio-net-pci,netdev=n0,mac=52:54:00:00:00:03 \
  -nographic



sudo iptables -P FORWARD ACCEPT
sudo sysctl -w  net.ipv4.conf.all.arp_filter=1
