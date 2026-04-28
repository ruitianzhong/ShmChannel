#!/usr/bin/env python3
"""
PTY Controller - 为多个容器启动独立的load_config.py进程
"""

import sys
import subprocess
import time
import os

def main():
    if len(sys.argv) < 2:
        print("用法: python3 pty_controller.py 容器名1 容器名2 ...")
        print("示例: python3 pty_controller.py container1 container2 container3")
        sys.exit(1)
    
    # 获取容器名列表（跳过脚本名）
    container_names = sys.argv[1:]
    
    print(f"为 {len(container_names)} 个容器启动配置进程...")
    
    processes = []
    
    # 为每个容器启动独立的load_config.py进程
    for container_name in container_names:
        cmd = [sys.executable, "./load_config.py", "--name", container_name]
        
        print(f"启动容器 '{container_name}': {' '.join(cmd)}")
        
        try:
            # 启动子进程
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
            processes.append((container_name, process))
            
        except Exception as e:
            print(f"启动容器 '{container_name}' 失败: {e}")
    
    print(f"\n已启动 {len(processes)} 个进程")
    print("等待所有进程完成...")
    print("-" * 40)
    
    # 等待所有进程完成
    for container_name, process in processes:
        print(f"等待容器 '{container_name}' 完成...")
        
        # 读取并输出进程的stdout和stderr
        stdout, stderr = process.communicate()
        
        if stdout:
            print(f"[{container_name} stdout]:")
            print(stdout)
        
        if stderr:
            print(f"[{container_name} stderr]:")
            print(stderr)
        
        return_code = process.returncode
        if return_code == 0:
            print(f"容器 '{container_name}' 完成成功")
        else:
            print(f"容器 '{container_name}' 失败，退出码: {return_code}")
        
        print("-" * 40)
    
    print("所有进程处理完成")

if __name__ == "__main__":
    main()