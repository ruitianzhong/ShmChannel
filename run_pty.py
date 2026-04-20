import os
import pty
import time


def run_example_with_pty():
    master_fd, slave_fd = pty.openpty()

    pid = os.fork()
    if pid == 0:
        # 子进程：重定向输入输出到 pty
        os.close(master_fd)
        os.dup2(slave_fd, 0)
        os.dup2(slave_fd, 1)
        os.dup2(slave_fd, 2)
        os.close(slave_fd)

        # 执行你的程序
        os.execl("./example.py", "./example.py")

    # 父进程
    os.close(slave_fd)
    output_buffer = b""

    cmds = ["command1", "command2", "command3"]

    outputs = []

    ready = False
    idx = 0

    try:
        while True:

            data = os.read(master_fd, 1024)
            if not data:
                print("No Data")
                break

            output_buffer += data
            print("[Output]:", data.decode().strip())
            if b"[HUAWEI]" in output_buffer:
                if ready:
                    outputs.append(output_buffer.decode())
                    idx += 1
                    output_buffer = b""
                else:
                    ready = True
            else:
                # nothing to handle
                continue
            if idx == len(cmds):
                break
            os.write(master_fd, (cmds[idx]+"\n").encode())

            time.sleep(0.01)

    finally:
        os.close(master_fd)
        os.waitpid(pid, 0)

    return outputs


if __name__ == "__main__":
    final_outputs = run_example_with_pty()

    print(final_outputs)
