"""CPUProfiler - 周期性记录 CPU 利用率并在事件点绘制折线图。

用法示例:
    profiler = CPUProfiler(interval=0.5)
    profiler.start()
    # ... 执行被测逻辑 ...
    profiler.record("阶段A")
    # ... 更多逻辑 ...
    profiler.end()
    profiler.plot()
"""

import threading
import time

import matplotlib.pyplot as plt


class CPUProfiler:
    """每隔 interval 秒记录一次系统整体 CPU 利用率。

    通过对 /proc/stat (第一行 cpu 总和) 做两次差值，用 busy 与 total 之比
    得到整个系统（所有核）的 CPU 占用率，归一化到 0-100%。
    """

    def __init__(self, interval: float = 1.0):
        self.interval = interval
        self._lock = threading.Lock()
        self._thread = None
        self._stop_event = threading.Event()

        # 采样数据
        self._t: list[float] = []          # 每个采样点的墙钟时间（相对 start 的秒数）
        self._cpu_pct: list[float] = []    # 每个采样点的 CPU 利用率百分比
        self._events: list[tuple[float, str]] = []  # (时间, 事件名)

        self._epoch: float = 0.0  # start() 时的墙钟零点
        self._started = False

    # ------------------------------------------------------------------ #
    # 采样线程
    # ------------------------------------------------------------------ #
    @staticmethod
    def _read_system_cpu() -> tuple[int, int]:
        """读 /proc/stat 第一行 (cpu 总和)，返回 (busy, total)。"""
        with open("/proc/stat") as f:
            parts = f.readline().split()
        # 字段: cpu user nice system idle iowait irq softirq steal ...
        fields = parts[1:]
        idle = int(fields[3]) + int(fields[4])  # idle + iowait 视为空闲
        total = sum(int(v) for v in fields)
        return total - idle, total

    def _sample_loop(self):
        while not self._stop_event.is_set():
            start_wall = time.monotonic()

            busy0, total0 = self._read_system_cpu()
            # 多个采样点之间留出 interval，并落在均匀的时间轴上
            time.sleep(self.interval)
            busy1, total1 = self._read_system_cpu()

            d_busy, d_total = busy1 - busy0, total1 - total0
            # /proc/stat 的 tick 数正比于墙钟流逝，按实际核数归一化即可
            pct = (d_busy / d_total * 100.0) if d_total > 0 else 0.0

            with self._lock:
                # 统一以 start() 时刻 (_epoch) 作为时间轴零点，与 record() 对齐
                self._t.append(start_wall - self._epoch)
                self._cpu_pct.append(pct)

    # ------------------------------------------------------------------ #
    # 对外接口
    # ------------------------------------------------------------------ #
    def start(self):
        """在任意线程（含主线程）调用，自动在后台启动采样线程。"""
        if self._started:
            return
        self._started = True
        self._stop_event.clear()
        self._epoch = time.monotonic()  # 记录起始墙钟时间，作为时间轴零点
        self._events.clear()
        self._t.clear()
        self._cpu_pct.clear()

        self._thread = threading.Thread(target=self._sample_loop, daemon=True)
        self._thread.start()

    def record(self, name: str):
        """记录一个事件名及其发生时刻（相对 start 的秒数）。"""
        now = time.monotonic() - self._epoch
        with self._lock:
            self._events.append((now, name))

    def end(self):
        """停止采样。返回 (times, cpu_pct, events) 快照。"""
        if not self._started:
            raise RuntimeError("Profiler 尚未 start()，无法 end()。")
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=self.interval + 1.0)
        with self._lock:
            times = list(self._t)
            cpu_pct = list(self._cpu_pct)
            events = list(self._events)
        return times, cpu_pct, events

    # ------------------------------------------------------------------ #
    # 结果访问
    # ------------------------------------------------------------------ #
    @property
    def times(self):
        return list(self._t)

    @property
    def cpu_pct(self):
        return list(self._cpu_pct)

    @property
    def events(self):
        return list(self._events)

    def average(self) -> float:
        """所有采样点的平均 CPU 利用率。"""
        return sum(self._cpu_pct) / len(self._cpu_pct) if self._cpu_pct else 0.0

    # ------------------------------------------------------------------ #
    # 绘图
    # ------------------------------------------------------------------ #
    def plot(self, title: str = "CPU 利用率曲线", save_path: str | None = None):
        """绘制 CPU 利用率折线图并在事件点添加竖线标注。

        save_path 为 None 时调用 plt.show() 阻塞展示；否则保存到文件。
        """
        if not self._cpu_pct:
            print("[CPUProfiler] 没有采样数据，无法绘图。")
            return

        fig, ax = plt.subplots(figsize=(10, 4))

        ax.plot(self._t, self._cpu_pct, color="#1f77b4", linewidth=1.5,
                label="CPU 利用率 (%)")
        ax.set_xlabel("时间 (s)")
        ax.set_ylabel("CPU 利用率 (%)")
        ax.set_ylim(bottom=0)
        ax.grid(True, linestyle="--", alpha=0.4)
        ax.set_title(title)

        # 在事件位置绘制竖线 + 名称标注
        if self._events:
            for t, name in self._events:
                ax.axvline(x=t, color="#d62728", linestyle="--", alpha=0.8)
                ax.text(t, ax.get_ylim()[1] * 0.97, name,
                        rotation=60, ha="right", va="top",
                        fontsize=9, color="#d62728")

        ax.legend(loc="upper right")

        if save_path:
            fig.tight_layout()
            fig.savefig(save_path, dpi=120)
            print(f"[CPUProfiler] 已保存图表到: {save_path}")
        else:
            fig.tight_layout()
            plt.show()

        plt.close(fig)


if __name__ == "__main__":
    # 简单自测
    profiler = CPUProfiler(interval=0.2)
    profiler.start()
    profiler.record("开始")
    time.sleep(1.0)
    for _ in range(8):
        time.sleep(0.05)
        for _ in range(200000):
            _ = sum(range(100))
        profiler.record("计算")
    time.sleep(0.8)
    profiler.record("收尾")
    times, cpu, events = profiler.end()
    print(f"采样点: {len(cpu)}, 平均 CPU: {profiler.average():.1f}%")
    print("事件:", events)
    profiler.plot()