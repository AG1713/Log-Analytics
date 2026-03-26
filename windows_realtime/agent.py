import os
import sys
import ctypes
import requests
import subprocess
import winreg
from scapy.all import sniff, IP
from datetime import datetime, timezone

PROTOCOL_MAP = {6: "tcp", 17: "udp", 1: "icmp"}

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def checking(name_to_search: str):
    # 1. Check common installation directories first (More reliable than Registry)
    common_paths = [
        r"C:\Program Files\Npcap\npcap.sys",
        r"C:\Windows\System32\Npcap\wpcap.dll"
    ]
    for p in common_paths:
        if os.path.exists(p):
            return True

    paths = [
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        r"SOFTWARE\WOW64Node\Microsoft\Windows\CurrentVersion\Uninstall"
    ]
    for path in paths:
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as key:
                for i in range(winreg.QueryInfoKey(key)[0]):
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        with winreg.OpenKey(key, subkey_name) as subkey:
                            display_name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                            if name_to_search.lower() in display_name.lower():
                                return True
                    except (OSError, IndexError, FileNotFoundError):
                        continue
        except FileNotFoundError:
            continue
    return False

def installing_npcap():
    # Direct link to the latest stable installer
    url = "https://npcap.com/dist/npcap-1.80.exe" 
    installer_path = os.path.join(os.environ["TEMP"], "npcap_installer.exe")

    print("Downloading Npcap installer...")
    response = requests.get(url, stream=True)
    if response.status_code == 200:
        with open(installer_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
    
    print("Running installer... Please complete the installation window.")
    # Wait for the installer to finish before moving to sniffing
    subprocess.run([installer_path], check=True)
    print("Installation finished.")

def collecting_NetworkLogs(packet):
    if IP in packet:
        now = datetime.now(timezone.utc)
        data = {
            "time": now.strftime("%Y-%m-%d %H:%M:%S"),
            "src": packet[IP].src,
            "dst": packet[IP].dst,
            "proto": PROTOCOL_MAP.get(packet[IP].proto, "other")
        }
        print(f"[{data['time']}] {data['proto'].upper()}: {data['src']} -> {data['dst']}")

def main():
    # --- ELEVATION CHECK ---
    if not is_admin():
        print("Not running as Admin. Attempting to elevate...")
        # Re-run the script with admin rights
        # The '1' at the end shows the window; '0' would hide it
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        sys.exit() # Essential to stop the current (non-admin) process

    # --- MAIN LOGIC ---
    print("Checking for Npcap...")
    if not checking("Npcap"):
        try:
            installing_npcap()
        except Exception as e:
            print(f"Error during installation: {e}")
            return
    else:
        print("Npcap found!")

    print("Starting Sniffer... (Press Ctrl+C to stop)")
    try:
        sniff(prn=collecting_NetworkLogs, store=0)
    except Exception as e:
        print(f"Sniffing error: {e}")

if __name__ == "__main__":
    main()
