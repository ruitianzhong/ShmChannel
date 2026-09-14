"""PerfProfiler - 基于 Linux perf 的全机采样采集器。

采集 perf record（全机 + 调用栈），结束后可用 FlameGraph 工具生成火焰图 SVG。
所有耗时操作都在后台线程执行，不阻塞主线程。

依赖:
    - 系统装有 perf (linux-tools)，且需要 root 权限（全机采样）。
    - 火焰图需要 Brendan Gregg 的 FlameGraph 工具包:
      https://github.com/brendangregg/FlameGraph
      （解压后目录里有 flamegraph.pl 和 stackcollapse-perf.pl）

用法示例:
    from perf_profiler import PerfProfiler
    p = PerfProfiler(perf_data_path="/tmp/out.perf.data")
    p.start()                       # 立即返回，后台开始采集
    # ... 执行被测负载 ...
    p.stop()                        # 信号 perf 收尾，等待数据写盘，返回 Future
    p.stop_future.result()          # 等数据就绪
    svg = p.plot_flamegraph(toolkit_dir="/opt/FlameGraph", block=False)
    # svg.result() 拿到最终 SVG 路径
"""

import os
import shutil
import signal
import subprocess
import threading
from concurrent.futures import Future

import matplotlib.pyplot as plt  # noqa: F401  (保留，供需要时扩展)


class PerfProfiler:
    def __init__(self, perf_data_path: str = "perf.data", freq: int | None = None):
        """perf_data_path: perf.data 落盘位置；freq: 采样频率(Hz)。"""
        self.perf_data_path = perf_data_path
        self.freq = freq
        self._proc: subprocess.Popen | None = None
        self._running = False

    # ------------------------------------------------------------------ #
    # 采集控制
    # ------------------------------------------------------------------ #
    def start(self) -> None:
        """后台启动 `perf record -a -g`，立即返回，不阻塞主线程。"""
        if self._running:
            raise RuntimeError("已经在采集中，请先 stop()。")
        if shutil.which("perf") is None:
            raise RuntimeError("未找到 perf，请安装 linux-tools。")

        cmd = ["perf", "record", "-a", "-g", "-o", self.perf_data_path]
        if self.freq:
            cmd += ["-F", str(self.freq)]
        # 必须让 perf 读到自己的 stdin，否则 SIGINT 无法送达
        self._proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        self._running = True

    def stop(self, block: bool = False) -> Future:
        """向 perf 发送 SIGINT 收尾并等待数据写盘。

        返回 Future；采集最终化在后台线程进行，不阻塞调用方。
        block=True 时同步等待并返回该 Future。
        """
        if not self._running:
            raise RuntimeError("尚未 start()。")
        if self._proc is None:
            raise RuntimeError("内部状态异常。")

        fut: Future = Future()
        proc = self._proc
        self._running = False

        def _finalize():
            try:
                # perf record 收到 SIGINT 后优雅停止并写入数据
                proc.send_signal(signal.SIGINT)
                proc.stdin.close()  # type: ignore[union-attr]
                _, err = proc.communicate(timeout=120)
                if proc.returncode not in (0, 130):
                    fut.set_exception(RuntimeError(
                        f"perf 异常退出 rc={proc.returncode}: {err.decode(errors='replace')}"
                    ))
                    return
                if not os.path.exists(self.perf_data_path):
                    fut.set_exception(FileNotFoundError(
                        f"未生成数据文件: {self.perf_data_path}"))
                    return
                fut.set_result(self.perf_data_path)
            except Exception as e:  # noqa: BLE001
                fut.set_exception(e)

        threading.Thread(target=_finalize, daemon=True).start()
        if block:
            fut.result()
        return fut

    # ------------------------------------------------------------------ #
    # 火焰图
    # ------------------------------------------------------------------ #
    def plot_flamegraph(
        self,
        flamegraph_dir: str | None = None,
        output_svg: str = "flamegraph.svg",
        block: bool = False,
    ) -> Future:
        """生成火焰图。

        flamegraph_dir: FlameGraph 工具目录（含 flamegraph.pl /
            stackcollapse-perf.pl）；为 None 时到 PATH 中找。
        block=True 同步执行并返回该 Future。
        返回的 Future.result() 为最终 SVG 路径。
        """
        fold, flame = self._locate_tools(flamegraph_dir)
        fut: Future = Future()

        def _build():
            try:
                svg = self._run_pipeline(fold, flame, output_svg)
                fut.set_result(svg)
            except Exception as e:  # noqa: BLE001
                fut.set_exception(e)

        threading.Thread(target=_build, daemon=True).start()
        if block:
            fut.result()
        return fut

    # ------------------------------------------------------------------ #
    # 内部实现
    # ------------------------------------------------------------------ #
    @staticmethod
    def _locate_tools(flamegraph_dir: str | None):
        """定位 stackcollapse-perf.pl 和 flamegraph.pl。"""
        candidates = []
        if flamegraph_dir:
            candidates.append(flamegraph_dir)
        # 常见全局安装位置
        candidates += ["/opt/FlameGraph", "/usr/local/FlameGraph", "FlameGraph"]

        fold = flame = None
        for d in candidates:
            f1 = os.path.join(d, "stackcollapse-perf.pl")
            f2 = os.path.join(d, "flamegraph.pl")
            if os.path.isfile(f1) and os.path.isfile(f2):
                fold, flame = f1, f2
                break
        if not fold:
            fold = shutil.which("stackcollapse-perf.pl")
            flame = shutil.which("flamegraph.pl")
        if not (fold and flame):
            raise FileNotFoundError(
                "未找到 FlameGraph 工具 (stackcollapse-perf.pl / flamegraph.pl)。"
                "请下载 https://github.com/brendangregg/FlameGraph 并传入 flamegraph_dir。"
            )
        return fold, flame

    def _run_pipeline(self, fold_pl: str, flame_pl: str, output_svg: str) -> str:
        """perf script | stackcollapse-perf.pl | flamegraph.pl > output.svg。"""
        script = ["perf", "script", "-i", self.perf_data_path]
        p1 = subprocess.Popen(
            script, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        p2 = subprocess.Popen(
            ["perl", fold_pl], stdin=p1.stdout, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)
        p1.stdout.close()  # type: ignore[union-attr]

        with open(output_svg, "wb") as svg:
            p3 = subprocess.Popen(
                ["perl", flame_pl], stdin=p2.stdout, stdout=svg,
                stderr=subprocess.PIPE)
            p2.stdout.close()  # type: ignore[union-attr]
            p3.communicate(timeout=300)

        p1.wait(timeout=300)
        p2.wait(timeout=300)
        if p3.returncode != 0:
            err = p3.stderr.read().decode(errors="replace") if p3.stderr else ""
            raise RuntimeError(f"flamegraph.pl 失败: {err}")
        if not os.path.exists(output_svg):
            raise RuntimeError("火焰图未生成成功。")
        return output_svg


if __name__ == "__main__":
    # 简单自测（需要 root + perf + FlameGraph 工具）
    p = PerfProfiler(perf_data_path="/tmp/pp.perf.data", freq=99)
    print("starting perf record ...")
    p.start()
    threading.Event().wait(2)  # 模拟负载
    print("stopping ...")
    fut = p.stop()
    fut.result(timeout=130)
    print("data ready:", fut.result())
    if shutil.which("perl"):
        svg = p.plot_flamegraph(flamegraph_dir="/opt/FlameGraph", block=True)
        print("flamegraph:", svg)
    else:
        print("(no perl, skip flamegraph)")