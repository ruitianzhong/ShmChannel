#!/usr/bin/env python3
"""test_vm.py: VM pause/resume 测试。

用法与 vm.py 保持一致: 用 VM(name) 构造、is_running() 判断是否在跑,
pause()/resume() 经 QMP stop/cont 冻结/恢复 vCPU, 再用 QMP query-status 断言
真实状态为 paused / running, 并验证:
  - pause 后 guest 冻结: 新的 ssh 连接应连不上/超时;
  - resume 后 guest 恢复: 能再在里面执行命令。

默认测 vm1, 可用 TEST_VM 环境变量指定其它(如 TEST_VM=vm2)。
若目标 VM 未运行则自动启动并在测试结束后关闭(owned); 已在运行则不关它。
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from vm import VM, QMP, ID_RSA  # noqa: E402


def _qmp_status(vm):
    """经 QMP 读当前运行状态字符串(paused / running / ...)。"""
    q = QMP(vm.spec["qmp"])
    status = q.cmd("query-status")
    q.close()
    return status.get("return", {}).get("status")


def _guest_cmd(vm, command):
    """在 VM 内跑一条命令, 返回 stdout(失败抛异常)。用于确认 guest 真实可响应。"""
    r = vm.exec(command, check=True)
    out = r.stdout.decode(errors="replace").strip()
    print(f"    [{vm.name}] guest: {command} -> {out!r}", flush=True)
    return out


def _assert_ssh_down(vm, connect_timeout=3):
    """断言 guest 已冻结(不可 ssh): 新建 ssh 应失败或超时, 返回非 0。
    若暂停后 ssh 竟能成功, 说明 VM 未真实冻结, 测试失败。"""
    argv = ["ssh", "-i", ID_RSA,
            "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", f"ConnectTimeout={connect_timeout}",
            f"root@{vm.spec['vm_ip']}", "true"]
    try:
        r = subprocess.run(argv, capture_output=True,
                           timeout=connect_timeout + 3)
    except subprocess.TimeoutExpired:
        print(f"    [{vm.name}] pause 后 ssh 超时 (符合预期, guest 已冻结)",
              flush=True)
        return
    if r.returncode == 0:
        raise AssertionError(f"{vm.name} 暂停后 ssh 竟能成功, VM 未真实冻结!")
    print(f"    [{vm.name}] pause 后 ssh 失败 rc={r.returncode} (符合预期, guest 已冻结)",
          flush=True)


def test_pause_resume():
    name = os.environ.get("TEST_VM", "vm1")
    vm = VM(name)

    # 未运行则启动(owned, 结束关闭); 已在运行则直接复用不关闭
    owned = False
    if not vm.is_running():
        print(f"    {name} 未运行, 启动并等 boot ...", flush=True)
        vm.start().wait_boot()
        owned = True

    # 启动/接管后, 先在里面跑一条命令, 确认 guest 已正常响应(baseline)
    _guest_cmd(vm, "echo alive && hostname")

    paused = False
    try:
        assert vm.pause() is True, f"{name} pause() 返回 False"
        paused = True
        st = _qmp_status(vm)
        assert st == "paused", f"{name} 暂停后状态应为 paused, 实际 {st}"
        print(f"    [{name}] pause 验证通过: QMP status={st}", flush=True)

        # pause 后 guest 冻结: 新的 ssh 应连不上/超时
        _assert_ssh_down(vm)

        assert vm.resume() is True, f"{name} resume() 返回 False"
        paused = False
        st = _qmp_status(vm)
        assert st == "running", f"{name} 恢复后状态应为 running, 实际 {st}"
        print(f"    [{name}] resume 验证通过: QMP status={st}", flush=True)

        # resume 后 guest 必须真的能再执行命令(QMP running 只是外部状态, 验证响应)
        _guest_cmd(vm, "echo resumed_ok && uptime")

    finally:
        # 断言失败也不要把 VM 留在暂停态
        if paused:
            vm.resume()
        # 仅在我们自己启动的情况下才关闭
        if owned:
            vm.stop(verbose=False)
            print(f"    {name} 停止(owned)", flush=True)

    print(f"    [{name}] test_pause_resume PASS", flush=True)


if __name__ == "__main__":
    test_pause_resume()