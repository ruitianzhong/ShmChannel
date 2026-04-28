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
                        print(f"Waiting for prompt... (buffer: {repr(decoded[-50:])})")
                
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


if __name__ == "__main__":
    executor = PtyExecutor()
    
    result1 = executor.execute_command("show version")
    print("Command 1 output:")
    print(result1)
    
    result2 = executor.execute_command("display interface brief")
    print("\nCommand 2 output:")
    print(result2)
    
    executor.close()
