#!/usr/bin/env python3
"""
PTY Controller - 为多个容器启动独立的load_config.py进程
"""

import sys
import subprocess
import os
from datetime import datetime

def main():
    # 解析参数
    silent = False
    container_names = []
    
    for arg in sys.argv[1:]:
        if arg == "--silent" or arg == "-s":
            silent = True
        elif not arg.startswith("-"):
            container_names.append(arg)
    
    if not container_names:
        print("用法: python3 pty_controller.py [--silent|-s] 容器名1 容器名2 ...")
        print("示例: python3 pty_controller.py container1 container2 container3")
        print("       python3 pty_controller.py --silent container1 container2")
        sys.exit(1)
    
    print(f"为 {len(container_names)} 个容器启动配置进程...")
    if silent:
        print("静默模式: 子进程输出将重定向到 /dev/null")
    
    processes = []
    log_dir = "logs"
    
    # 如果不是静默模式，创建日志目录
    if not silent and not os.path.exists(log_dir):
        os.makedirs(log_dir)
        print(f"创建日志目录: {log_dir}")
    
    # 为每个容器启动独立的load_config.py进程
    for container_name in container_names:
        cmd = ["python", "./pty_control.py", "--name", container_name]
        
        if silent:
            # 静默模式：重定向到 /dev/null
            stdout_dest = subprocess.DEVNULL
            stderr_dest = subprocess.DEVNULL
            print(f"启动容器 '{container_name}' (静默模式): {' '.join(cmd)}")
        else:
            # 正常模式：重定向到日志文件
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            stdout_log = os.path.join(log_dir, f"{container_name}_{timestamp}_stdout.log")
            stderr_log = os.path.join(log_dir, f"{container_name}_{timestamp}_stderr.log")
            stdout_dest = open(stdout_log, 'w')
            stderr_dest = open(stderr_log, 'w')
            print(f"启动容器 '{container_name}': {' '.join(cmd)}")
            print(f"  stdout -> {stdout_log}")
            print(f"  stderr -> {stderr_log}")
        
        try:
            # 启动子进程
            process = subprocess.Popen(
                cmd,
                stdout=stdout_dest,
                stderr=stderr_dest,
                text=True,
                bufsize=1
            )
            
            if silent:
                processes.append((container_name, process, None, None))
            else:
                processes.append((container_name, process, stdout_dest, stderr_dest))
            
        except Exception as e:
            print(f"启动容器 '{container_name}' 失败: {e}")
            # 如果不是静默模式，关闭已打开的文件
            if not silent:
                if 'stdout_dest' in locals() and not isinstance(stdout_dest, int):
                    stdout_dest.close()
                if 'stderr_dest' in locals() and not isinstance(stderr_dest, int):
                    stderr_dest.close()
    
    print(f"\n已启动 {len(processes)} 个进程")
    print("等待所有进程完成...")
    print("-" * 40)
    
    # 等待所有进程完成
    for container_name, process, stdout_file, stderr_file in processes:
        print(f"等待容器 '{container_name}' 完成...")
        
        # 等待进程完成
        return_code = process.wait()
        
        # 如果不是静默模式，关闭日志文件
        if not silent and stdout_file:
            stdout_file.close()
        if not silent and stderr_file:
            stderr_file.close()
        
        if return_code == 0:
            print(f"容器 '{container_name}' 完成成功")
        else:
            print(f"容器 '{container_name}' 失败，退出码: {return_code}")
        
        print("-" * 40)
    
    print("所有进程处理完成")

if __name__ == "__main__":
    main()