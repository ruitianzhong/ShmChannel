# -*- coding: utf-8 -*-
"""VM 管理基础: 通用工具 / host 网络 / QMP 客户端 / SSH 客户端 / VM 类。"""
import json
import os
import socket
import subprocess
import time

import topo

HERE = os.path.dirname(os.path.abspath(__file__))
ID_RSA = os.path.join(HERE, "id_rsa")

# 全局转发所需参数, 确保 vm1<->vm2 经 host 互通
HOST_SYSCTL = [
    "net.ipv4.ip_forward=1",
    "net.ipv4.conf.all.forwarding=1",
    "net.ipv4.conf.all.rp_filter=0",
    "net.ipv4.conf.all.arp_filter=1",
]


def _load_json(path):
    """直接解析一个 json 文件(不再做字段级覆盖/合并)。"""
    with open(path) as f:
        return json.load(f)


def _write_json(obj, path):
    with open(path, "w") as f:
        json.dump(obj, f, indent=2)
    return path


# ---------------------------------------------------------------- host 网络
def sh(cmd, check=True, capture=False):
    """统一跑 shell, 支持非 root 时用 sudo。"""
    if os.geteuid() != 0:
        cmd = "sudo " + cmd
    r = subprocess.run(cmd, shell=True, text=True,
                       capture_output=capture)
    if check and r.returncode != 0:
        raise RuntimeError(f"cmd failed ({r.returncode}): {cmd}\n{r.stderr}")
    return r


def tap_exists(tap):
    return os.path.exists(f"/sys/class/net/{tap}")


def setup_host_network():
    """创建/重建 tap、配置 host 侧 IP、开转发。"""
    # 只对实际存在的接口设转发(all 是通配) + 全局转发开关
    for k in list(HOST_SYSCTL) + ["net.ipv4.conf.all.forwarding=1"]:
        sh(f"sysctl -w {k}")
    # 放行 FORWARD, 避免 iptables 默认策略 DROP 挡掉转发
    sh("iptables -P FORWARD ACCEPT")

    for spec in topo.VMSPEC.values():
        _setup_single_tap(spec)
        sh(f"sysctl -w net.ipv4.conf.{spec['tap']}.forwarding=1")


def _setup_single_tap(spec):
    tap = spec["tap"]
    if tap_exists(tap):
        sh(f"ip link del {tap}")
    sh(f"ip tuntap add dev {tap} mode tap")
    sh(f"ip link set {tap} up")
    sh(f"ip addr add {spec['host_ip']} dev {tap}")


# ---------------------------------------------------------------- QMP 客户端
class QMP:
    def __init__(self, sock):
        self.sock = sock
        self._s = None

    def _connect(self):
        self._s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._s.settimeout(2)
        self._s.connect(self.sock)

    def _recv(self):
        # QMP 每对象以 \n 结尾; 但 一次 recv 可能带回多行(命令返回 + 异步事件),
        # 故逐行解析返回对象列表。解析失败时把原始字节打印出来, 辅助定位。
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = self._s.recv(4096)
            if not chunk:
                break
            buf += chunk
        objs = []
        for ln in buf.split(b"\n"):
            ln = ln.strip()
            if not ln:
                continue
            try:
                objs.append(json.loads(ln))
            except json.JSONDecodeError as e:
                print(f"[QMP] 解析失败 raw={buf!r} err={e}", flush=True)
                raise
        return objs

    def cmd(self, execute, **kwargs):
        if self._s is None:
            self._connect()
            self._recv()  # greeting(忽略)
            self.cmd("qmp_capabilities")
        self._s.sendall((json.dumps({"execute": execute, "arguments": kwargs}) + "\n").encode())
        # 跳过异步事件(event), 直到拿到本命令的返回或错误
        while True:
            for o in self._recv():
                if "event" in o:
                    continue
                return o

    def close(self):
        if self._s:
            self._s.close()
            self._s = None


# ---------------------------------------------------------------- SSH 客户端
def wait_ssh_ready(vm_ip, timeout=90, interval=2):
    base = ["ssh", "-i", ID_RSA,
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "LogLevel=ERROR",
            "-o", "ConnectTimeout=2",
            f"root@{vm_ip}", "true"]
    end = time.time() + timeout
    while time.time() < end:
        r = subprocess.run(base, capture_output=True)
        if r.returncode == 0:
            return
        time.sleep(interval)
    raise TimeoutError(f"SSH not ready for {vm_ip} after {timeout}s")


# ---------------------------------------------------------------- VM 类
class VM:
    def __init__(self, name, memory=1024, cpus=2, console=False,
                 base_dir=None, ssh_port=None, spec=None):
        """name ∈ {vm1, vm2}; spec 显式给出时可不依赖全局 VMSPEC(供自动创建)。"""
        if spec is None:
            if name not in topo.VMSPEC:
                raise ValueError(f"unknown vm: {name}, choice={list(topo.VMSPEC)}")
            self.spec = topo.VMSPEC[name]
        else:
            self.spec = spec
        self.name = name
        self.base_dir = base_dir or HERE
        self.memory = memory
        self.cpus = cpus
        self.console = console
        self.img_path = os.path.join(self.base_dir, self.spec["img"])
        # 可选: 用 slirp hostfwd 给 VM 额外开一个 ssh 端口(便于从外部连)
        self.ssh_port = ssh_port
        self._proc = None

    # ---- 生命周期
    def start(self):
        if self.is_running():
            raise RuntimeError(f"{self.name} 已在运行")
        cmd = [
            "qemu-system-x86_64",
            "-enable-kvm", "-m", str(self.memory), "-smp", str(self.cpus),
            "-cpu", "host",
            "-drive", f"file={self.img_path},format=qcow2,if=virtio",
            "-netdev", f"tap,id=n0,ifname={self.spec['tap']},script=no,downscript=no",
            "-device", f"virtio-net-pci,netdev=n0,mac={self.spec['mac']}",
            "-qmp", f"unix:{self.spec['qmp']},server,nowait",
        ]
        if self.spec.get("guest_cid"):
            cmd += ["-device", f"vhost-vsock-pci,guest-cid={self.spec['guest_cid']}"]
        if self.ssh_port:
            cmd += ["-netdev", f"user,id=ssh,hostfwd=tcp::{self.ssh_port}-:22",
                    "-device", "virtio-net-pci,netdev=ssh"]
        if self.console:
            cmd += ["-display", "none", "-serial", "stdio", "-nographic"]
        else:
            cmd += ["-display", "none", "-daemonize"]

        # qmp socket 可能残留(root 所有), 先清掉
        if os.path.exists(self.spec["qmp"]):
            sh(f"rm -f {self.spec['qmp']}")
        if self.console:
            self._proc = subprocess.Popen(cmd)  # 前台, 独占终端
        else:
            sh(" ".join(cmd))  # daemonize 由 qemu 自行后台
        return self

    def wait_boot(self, timeout=120):
        wait_ssh_ready(self.spec["vm_ip"], timeout=timeout)
        return self

    def is_running(self):
        return bool(subprocess.run(
            ["pgrep", "-f", self.spec["img"]], capture_output=True).stdout)

    # ---- 操作
    def exec(self, command, check=True, capture=True):
        """在 VM 内执行 shell 命令, 返回 subprocess.CompletedProcess。"""
        argv = ["ssh", "-i", ID_RSA,
                "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null",
                "-o", "LogLevel=ERROR",
                f"root@{self.spec['vm_ip']}", command]
        r = subprocess.run(argv, capture_output=capture)
        if check and r.returncode != 0:
            raise RuntimeError(f"remote cmd failed ({r.returncode}): {command}")
        return r

    def scp_exec(self, cmd):
        """scp: put/get 的底层。cmd 例如 '/tmp/f' root@ip:/root/ """
        r = subprocess.run((f"scp -i {ID_RSA} "
                            f"-o StrictHostKeyChecking=no "
                            f"-o UserKnownHostsFile=/dev/null "
                            f"-o LogLevel=ERROR {cmd}").split(" "))
        if r.returncode != 0:
            raise RuntimeError(f"scp failed: {cmd}")
        return r

    def run_script(self, script, check=True):
        """经 ssh stdin 在 VM 内以 bash 执行整段脚本(避免逐条命令往返)。

        script 是远端 shell 脚本字符串; 返回 subprocess.CompletedProcess。
        """
        argv = ["ssh", "-i", ID_RSA,
                "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null",
                "-o", "LogLevel=ERROR",
                f"root@{self.spec['vm_ip']}", "bash", "-s"]
        r = subprocess.run(argv, input=script, capture_output=True,
                           text=True)
        if check and r.returncode != 0:
            raise RuntimeError(
                f"remote script failed ({r.returncode}) on {self.name}:\n{r.stdout}\n{r.stderr}")
        return r

    def put(self, local, remote):
        """上传文件到 VM 内。local 宿主机路径, remote VM 内绝对路径。"""
        return self.scp_exec(f"{local} root@{self.spec['vm_ip']}:{remote}")

    def get(self, remote, local):
        """从 VM 内下载文件到宿主机。"""
        return self.scp_exec(f"root@{self.spec['vm_ip']}:{remote} {local}")

    def pause(self, label=None):
        """冻结 VM(vCPU 暂停, 经 QMP stop)。返回是否成功。"""
        tag = label or self.name
        if not self.is_running():
            return False
        try:
            q = QMP(self.spec["qmp"])
            q.cmd("stop")
            q.close()
            print(f"    {tag} 已暂停 [qmp-stop]", flush=True)
            return True
        except Exception as e:
            print(f"    {tag} 暂停失败: {type(e).__name__}: {e}", flush=True)
            return False

    def resume(self, label=None):
        """恢复冻结的 VM(vCPU 继续, 经 QMP cont)。返回是否成功。"""
        tag = label or self.name
        if not self.is_running():
            return False
        try:
            q = QMP(self.spec["qmp"])
            q.cmd("cont")
            q.close()
            print(f"    {tag} 已恢复 [qmp-cont]", flush=True)
            return True
        except Exception as e:
            print(f"    {tag} 恢复失败: {type(e).__name__}: {e}", flush=True)
            return False

    def stop(self, force=False, verbose=True, label=None):
        """关闭 VM。返回实际采用的退出方式字符串。

        退出方式(优先序):
          - "guest-shutdown": 让 VM 内 shutdown -h now (最优雅)
          - "qmp-quit":       通过 QMP 发 quit (优雅且立即)
          - "kill":           强制 pkill -9 (兜底)
        force=True 时直接走 "kill"。
        verbose 控制是否打印退出方式; label 可自定义打印前缀(默认用 VM 名)。
        """
        if not self.is_running():
            return None
        tag = label or self.name
        if force:
            sh(f"pkill -9 -f {self.spec['img']}")
            self._report(tag, "kill", verbose)
            return "kill"
        # 优雅方式1: 让 VM 内 shut down
        try:
            self.exec("shutdown -h now", check=False)
            time.sleep(3)
        except Exception:
            pass
        # 优雅方式2: QMP quit (立即退出 qemu)
        try:
            q = QMP(self.spec["qmp"])
            q.cmd("quit")
            q.close()
            self._report(tag, "qmp-quit", verbose)
            return "qmp-quit"
        except Exception:
            sh(f"pkill -9 -f {self.spec['img']}")
            self._report(tag, "kill", verbose)
            return "kill"

    @staticmethod
    def _report(tag, method, verbose):
        if verbose:
            print(f"    {tag} 已停止 [{method}]", flush=True)

    # ---- 上下文管理器
    def __enter__(self):
        return self

    def __exit__(self, *args):
        if self.is_running():
            self.stop()
        return False