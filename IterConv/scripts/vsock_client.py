#!/usr/bin/env python3
"""vsock 控制 client: 连接 VM 内的 vsock server, 下发网络配置并打印应答。

用法(宿主机上运行, host 恒为 cid 2):
    ./vsock_client.py <guest_cid> [--ip <IP/LEN>] [--gw <网关>] [-p 端口]
例:
    ./vsock_client.py 4 --ip 192.168.0.6/30 --gw 192.168.0.5   # 配 ens3 IP + 默认路由
    ./vsock_client.py 4 --gw 192.168.0.5                        # 只配默认路由(兼容旧用法)

应答逐行含各命令 rc=N, 由调用方据此判断成功。
"""
import argparse
import socket


def main():
    ap = argparse.ArgumentParser(description="vsock 控制 client")
    ap.add_argument("cid", type=int, nargs="?", default=3, help="目标 guest cid")
    ap.add_argument("--ip", default=None, metavar="IP/LEN",
                    help="ens3 地址(如 192.168.0.6/30); 省略则只配网关")
    ap.add_argument("--gw", default="192.168.0.5", metavar="IP", help="默认网关")
    ap.add_argument("-p", "--port", type=int, default=12345, help="vsock 端口")
    a = ap.parse_args()

    payload = f"{a.ip} {a.gw}" if a.ip else a.gw

    s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    s.connect((a.cid, a.port))
    s.sendall(payload.encode())
    s.shutdown(socket.SHUT_WR)                     # 关写端: 告诉 server 参数已发完
    buf = b""
    while True:
        chunk = s.recv(4096)
        if not chunk:
            break
        buf += chunk
    s.close()
    print(buf.decode())


if __name__ == "__main__":
    main()