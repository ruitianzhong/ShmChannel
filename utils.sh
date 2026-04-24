sudo ip addr add 192.168.0.2/24 dev tap0

sudo systemctl disable systemd-networkd-wait-online.service
sudo systemctl mask systemd-networkd-wait-online.service

sudo ip addr add 192.168.0.3/24 dev ens3
sudo ip l set ens3 up

sudo ip tuntap add dev tap0 mode tap
sudo ip addr add 192.168.0.2/24 dev tap0

qemu-img create -f qcow2 -b jammy-server-cloudimg-amd64.img -F qcow2 vm1.qcow2

pip install qemu.qmp
sudo chmod +x /etc/rc.local 
sudo cat > /usr/local/bin/setip.sh <<EOF
#!/bin/bash
ip addr add 192.168.0.3/24 dev ens3
ip l set ens3 up
EOF

sudo chmod +x /usr/local/bin/setip.sh

sudo cat > /etc/systemd/system/setip.service <<EOF
[Unit]
Description=Set static IP on boot
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/setip.sh

[Install]
WantedBy=multi-user.target
EOF

# 4. 启用并启动
sudo systemctl daemon-reload
sudo systemctl enable setip
sudo systemctl start setip

nc -U ./qmp-restore-sock