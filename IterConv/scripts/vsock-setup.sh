

# ============ vsock 控制 server/client ============
# 目的: client 从宿主机经 vsock 给 VM 下发网关 IP, server 在 VM 内执行:
#   ip link set dev ens3 up
#   ip route replace default via <GW> dev ens3
# 代码: scripts/vsock_server.py(跑在 VM) / scripts/vsock_client.py(跑在宿主机)

# 1) 宿主机: 加载 vsock 内核模块(如未加载)
sudo modprobe vhost_vsock

# 2) QEMU 启动须加 vsock 设备, guest-cid 每个 VM 唯一(host 恒为 2):
#    vm1 用 3, vm2 用 4, vm3 用 5
#    -device vhost-vsock-pci,guest-cid=3    # 加到 vm1 的 qemu 启动行

# 3) 把 server 拷进 VM 并设为开机自启(以 vm2, cid=4 为例)
# scp -i id_rsa scripts/vsock_server.py root@192.168.0.6:/root/
ssh -i id_rsa root@192.168.0.6 'python3 - <<EOF
import subprocess
srv = open("/root/vsock_server.py","r").read()
with open("/etc/systemd/system/vsock-ctl.service","w") as f:
    f.write("""[Unit]
Description=vsock network control server
After=network.target

[Service]
ExecStart=/usr/bin/python3 /root/vsock_server.py
Restart=always
RestartSec=1

[Install]
WantedBy=multi-user.target
""")
subprocess.run("chmod +x /root/vsock_server.py && systemctl daemon-reload && systemctl enable --now vsock-ctl.service", shell=True, check=True)
print("vsock-ctl.service installed & enabled")
EOF'

# 4) 宿主机侧下发网关(连接 cid=4 的 VM2, 下 192.168.0.5)
python3 scripts/vsock_client.py 4 --gw 192.168.0.5

# 5) 验证 VM 内生效
ssh -i id_rsa root@192.168.0.6 'ip route; ip -br link show ens3'
