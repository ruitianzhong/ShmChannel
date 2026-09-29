#!/usr/bin/env python3
"""vsock 控制 server: 在 VM 内监听 vsock, 收到客户端下发的参数后配置网络。

参数(一行, 空格分隔, 向后兼容):
    "<vm_ip>/<len> <gateway>"    -> 设置 ens3 IP + 路由 + 起网卡(如 "192.168.0.6/30 192.168.0.5")
    或仅 "<gateway>"             -> 只配默认路由 + 起网卡(旧用法)

执行:
    ip addr replace dev ens3 <vm_ip>/<len>   (仅当给了 IP)
    ip link set dev ens3 up
    ip route replace default via <gateway> dev ens3

用法: 端口用环境变量 PORT 指定(默认 12345)。以 root 运行(开机自启即 root)。
"""
import os
import socket
import subprocess

CID_ANY = 0xFFFFFFFF          # VMADDR_CID_ANY
PORT = int(os.environ.get("PORT", "12345"))


def handle(conn, addr):
    with conn:
        data = conn.recv(4096)
        txt = data.decode().strip()
        tokens = txt.split()
        ipadr = tokens[0] if len(tokens) >= 2 else None   # 可空: 兼容只发网关
        gw = tokens[-1]
        print(f"[vsock] 从 {addr} 收到: {txt!r}", flush=True)

        cmds = []
        if ipadr:
            cmds.append(f"ip addr replace dev ens3 {ipadr}")
        cmds.append("ip link set dev ens3 up")
        cmds.append(f"ip route replace default via {gw} dev ens3")

        lines = []
        for c in cmds:
            r = subprocess.run(c, shell=True, capture_output=True, text=True)
            print(f"[vsock] $ {c} -> rc={r.returncode}", flush=True)
            if r.stdout.strip() or r.stderr.strip() or r.returncode != 0:
                print(f"           stdout: {r.stdout.strip()}", flush=True)
                print(f"           stderr: {r.stderr.strip()}", flush=True)
            lines.append(f"# {c}\nrc={r.returncode}\n{r.stdout.strip()}\n{r.stderr.strip()}")
        conn.sendall(("\n".join(lines)).encode())


def main():
    srv = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    srv.bind((CID_ANY, PORT))
    srv.listen(1)
    print(f"[vsock] server listening cid={CID_ANY:#x} port={PORT}", flush=True)
    while True:
        conn, addr = srv.accept()
        handle(conn, addr)


if __name__ == "__main__":
    main()