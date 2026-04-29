#!/usr/bin/env python3
"""
PTY Controller - 为多个容器启动独立的load_config.py进程
"""

import sys
import subprocess
import os
from datetime import datetime

def main():
    if len(sys.argv) < 2:
        print("用法: python3 pty_controller.py 容器名1 容器名2 ...")
        print("示例: python3 pty_controller.py container1 container2 container3")
        sys.exit(1)
    
    # 获取容器名列表（跳过脚本名）
    container_names = sys.argv[1:]
    
    print(f"为 {len(container_names)} 个容器启动配置进程...")
    
    processes = []
    log_dir = "logs"
    
    # 创建日志目录
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
        print(f"创建日志目录: {log_dir}")
    
    # 为每个容器启动独立的load_config.py进程
    for container_name in container_names:
        cmd = ["python", "./pty_control.py", "--name", container_name]
        
        # 生成日志文件名（包含时间戳）
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        stdout_log = os.path.join(log_dir, f"{container_name}_{timestamp}_stdout.log")
        stderr_log = os.path.join(log_dir, f"{container_name}_{timestamp}_stderr.log")
        
        print(f"启动容器 '{container_name}': {' '.join(cmd)}")
        print(f"  stdout -> {stdout_log}")
        print(f"  stderr -> {stderr_log}")
        
        try:
            # 打开日志文件
            stdout_file = open(stdout_log, 'w')
            stderr_file = open(stderr_log, 'w')
            
            # 启动子进程，重定向输出到文件
            process = subprocess.Popen(
                cmd,
                stdout=stdout_file,
                stderr=stderr_file,
                text=True,
                bufsize=1
            )
            processes.append((container_name, process, stdout_file, stderr_file))
            
        except Exception as e:
            print(f"启动容器 '{container_name}' 失败: {e}")
            # 关闭已打开的文件
            if 'stdout_file' in locals():
                stdout_file.close()
            if 'stderr_file' in locals():
                stderr_file.close()
    
    print(f"\n已启动 {len(processes)} 个进程")
    print("等待所有进程完成...")
    print("-" * 40)
    
    # 等待所有进程完成
    for container_name, process, stdout_file, stderr_file in processes:
        print(f"等待容器 '{container_name}' 完成...")
        
        # 等待进程完成
        return_code = process.wait()
        
        # 关闭日志文件
        stdout_file.close()
        stderr_file.close()
        
        if return_code == 0:
            print(f"容器 '{container_name}' 完成成功")
        else:
            print(f"容器 '{container_name}' 失败，退出码: {return_code}")
        
        print("-" * 40)
    
    print("所有进程处理完成")

if __name__ == "__main__":
    main()