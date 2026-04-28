import ipaddress
import os
import pty
import time


class PtyExecutor:
    def __init__(self, program_path="./time_client", password="password"):
        self.master_fd, slave_fd = pty.openpty()
        self.pid = os.fork()

        if self.pid == 0:
            os.close(self.master_fd)
            os.dup2(slave_fd, 0)
            os.dup2(slave_fd, 1)
            os.dup2(slave_fd, 2)
            os.close(slave_fd)
            os.execl(program_path, program_path)

        os.close(slave_fd)
        self._login(password)

    def _login(self, password):
        output_buffer = b""
        entered_password = False
        max_attempts = 10
        attempts = 0

        print(f"Starting login process (max attempts: {max_attempts})")

        while attempts < max_attempts:
            try:
                print(f"Login attempt {attempts + 1}/{max_attempts}")
                data = os.read(self.master_fd, 1024)
                if not data:
                    print("No data received from PTY, continuing to wait...")
                    attempts += 1
                    time.sleep(0.1)
                    continue

                output_buffer += data
                decoded = output_buffer.decode()
                print(f"Received: {repr(decoded)}")

                if not entered_password:
                    if "Password:" in decoded or "password:" in decoded.lower():
                        print("Password prompt detected, sending password...")
                        os.write(self.master_fd, (password + "\n").encode())
                        entered_password = True
                        output_buffer = b""
                        print("Password sent")
                    elif "[HUAWEI]" in decoded or "<HUAWEI>" in decoded:
                        print("Prompt detected, login successful")
                        break
                    else:
                        print("Sending Enter key...")
                        os.write(self.master_fd, b"\n")
                else:
                    if "[HUAWEI]" in decoded or "<HUAWEI>" in decoded:
                        print("Prompt detected after password, login successful")
                        break
                    else:
                        print(
                            f"Waiting for prompt... (buffer: {repr(decoded[-50:])})")

                attempts += 1
                time.sleep(0.1)
            except OSError as e:
                print(f"OSError during login: {e}")
                break

        if attempts >= max_attempts:
            raise Exception("Login timeout")
        else:
            print("Login process completed")

    def execute_command(self, command):
        os.write(self.master_fd, (command + "\n").encode())
        output_buffer = b""

        while True:
            try:
                data = os.read(self.master_fd, 1024)
                if not data:
                    break

                output_buffer += data
                decoded = output_buffer.decode()

                if "[HUAWEI]" in decoded or "<HUAWEI>" in decoded:
                    break
            except OSError:
                break

            time.sleep(0.01)

        result = output_buffer.decode()
        lines = result.split('\n')
        cleaned_lines = []
        for line in lines:
            if line.strip() not in ["[HUAWEI]", "<HUAWEI>", "[HUAWEI] ", "<HUAWEI> "]:
                cleaned_lines.append(line)
        return '\n'.join(cleaned_lines).strip()

    def close(self):
        try:
            os.write(self.master_fd, b'\x1d')
            time.sleep(0.1)
        except:
            pass
        finally:
            os.close(self.master_fd)
            os.waitpid(self.pid, 0)


def generate_configure_commands(num_routes, start_ip="10.2.1.1", next_hop="172.20.6.100"):
    cmds = []

    cmds.extend(
        ["sys", "interface GigabitEthernet0/7/1", "undo shutdown",
            "ip address 172.20.6.66 255.255.255.0", "undo dcn", "commit", "quit"]
    )
    ip = ipaddress.IPv4Address(start_ip)

    for idx in range(num_routes):
        current_ip = str(ip)
        cmds.append(f"ip route-static {current_ip} 255.255.255.255 {next_hop}")
        ip += 1

    return cmds


def run_example_with_pty():
    master_fd, slave_fd = pty.openpty()

    pid = os.fork()
    if pid == 0:

        os.close(master_fd)
        os.dup2(slave_fd, 0)
        os.dup2(slave_fd, 1)
        os.dup2(slave_fd, 2)
        os.close(slave_fd)

        os.execl("./pty_terminal.py", "./pty_terminal.py")

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


def execute_configure_commands_and_log(num_routes, start_ip="10.2.1.1", next_hop="172.20.6.100", 
                                       program_path="./time_client", password="password", 
                                       log_file="configure_commands.log"):
    """
    使用PtyExecutor执行generate_configure_commands生成的命令，并将输出保存到日志文件
    
    Args:
        num_routes: 要生成的路由数量
        start_ip: 起始IP地址
        next_hop: 下一跳地址
        program_path: PTY程序路径
        password: 登录密码
        log_file: 日志文件路径，如果为None则不保存日志文件
    """
    import datetime
    
    # 生成配置命令
    commands = generate_configure_commands(num_routes, start_ip, next_hop)
    
    print(f"Generated {len(commands)} commands to execute")
    
    # 是否记录日志的标志
    enable_logging = log_file is not None
    if enable_logging:
        print(f"Logging output to: {log_file}")
    else:
        print("Logging disabled (log_file=None)")
    
    # 在内存中构建日志内容（即使不保存文件也记录，用于控制台显示）
    log_content = []
    
    # 添加日志头
    if enable_logging:
        log_content.append(f"Configuration Execution Log")
        log_content.append(f"Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        log_content.append(f"Number of commands: {len(commands)}")
        log_content.append(f"Program: {program_path}")
        log_content.append("="*80)
        log_content.append("")
    
    try:
        # 创建PtyExecutor
        executor = PtyExecutor(program_path=program_path, password=password)
        
        # 执行每个命令
        for i, cmd in enumerate(commands, 1):
            command_log = []
            if enable_logging:
                command_log.append(f"\n{'='*60}")
                command_log.append(f"COMMAND {i}/{len(commands)}: {cmd}")
                command_log.append(f"{'='*60}")
                command_log.append(f"Timestamp: {datetime.datetime.now().strftime('%H:%M:%S.%f')}")
                command_log.append("-"*60)
            
            print(f"[{i}/{len(commands)}] Executing: {cmd}")
            
            try:
                # 执行命令
                output = executor.execute_command(cmd)
                
                # 记录输出
                if enable_logging:
                    command_log.append(f"OUTPUT:\n{output}")
                
                # 在控制台显示简要信息
                output_preview = output[:200] + ("..." if len(output) > 200 else "")
                print(f"  Output ({len(output)} chars): {output_preview}")
                
            except Exception as e:
                error_msg = f"ERROR executing command: {e}"
                if enable_logging:
                    command_log.append(f"ERROR:\n{error_msg}")
                print(f"  {error_msg}")
            
            # 将单个命令的日志添加到总日志内容
            if enable_logging:
                log_content.extend(command_log)
            
            # 命令间短暂延迟
            # time.sleep(0.1)
        
        # 关闭执行器
        executor.close()
        
        # 添加执行完成信息
        if enable_logging:
            log_content.append(f"\n{'='*80}")
            log_content.append(f"EXECUTION COMPLETED SUCCESSFULLY")
            log_content.append(f"Total commands executed: {len(commands)}")
            log_content.append(f"End time: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        if enable_logging:
            print(f"\nExecution completed. Saving log to: {log_file}")
        else:
            print(f"\nExecution completed. No log file saved.")
        
    except Exception as e:
        error_msg = f"FATAL ERROR: {e}"
        if enable_logging:
            log_content.append(f"\n{error_msg}")
            log_content.append(f"Execution terminated at: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"\n{error_msg}")
        
        # 即使出错也保存已收集的日志（如果启用了日志）
        if enable_logging:
            with open(log_file, 'w', encoding='utf-8') as f:
                f.write('\n'.join(log_content))
        raise
    
    # 一次性写入日志文件（如果启用了日志）
    if enable_logging:
        with open(log_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(log_content))
        return log_file
    else:
        return None


if __name__ == "__main__":
    # 测试执行配置命令
    print("Testing configuration command execution...")
    
    # 执行5条路由配置命令
    log_file = execute_configure_commands_and_log(
        num_routes=5,
        start_ip="10.2.1.1",
        next_hop="172.20.6.100",
        program_path="./time_client",
        password="password",
        log_file="configure_test.log"
    )
    
    print(f"Test completed. Check {log_file} for details.")
