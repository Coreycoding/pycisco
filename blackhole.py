"""
Input:

A ptext file containing target device IPs (one per line).

Another text file containing one or more config commands (one per line) to be sent.

Ensure the script and text files are in the same directory as python.

For each device:

SSH from the aggregation switch to the device.

Execute `show interfaces status` to gather port information.

Find ports that are both 'notconnect' and have a blank 'Name' field.

Enter config mode and send all config commands from file (in order) to each matching port.

Issue 'do write' to save the configuration changes.

Exit back to the aggregation switch, continue to the next device.

Sample Usage
python blackhole_ports.py devices.txt config.txt

devices.txt contains:

192.168.1.1
192.168.1.2

config.txt contains:

 description BLACKHOLE
 switchport access vlan 999
 switchport mode access
 switchport nonegotiate
 shutdown
 no cdp enable

"""

#!/usr/bin/env python3

import paramiko
import time
import sys
import re

# USER CONFIG
AGG_IP = "192.168.1.1"
USERNAME = "admin"
PASSWORD = "cisco"
TIMEOUT = 10
MAX_READ = 65535

def expect_prompt(shell, patterns=("#", ">"), timeout=TIMEOUT):
    buf, end = "", time.time() + timeout
    while time.time() < end:
        if shell.recv_ready():
            data = shell.recv(MAX_READ).decode("utf-8", "ignore")
            buf += data
            for p in patterns:
                if p in buf:
                    return buf
        else:
            time.sleep(0.1)
    return buf

def send_cmd(shell, cmd, patterns=("#", ">"), timeout=TIMEOUT):
    shell.send(cmd + "\n")
    return expect_prompt(shell, patterns, timeout)

def connect_to_agg():
    print(f"[CONNECT] SSH to aggregation switch: {AGG_IP}")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(AGG_IP, username=USERNAME, password=PASSWORD,
                   look_for_keys=False, allow_agent=False, timeout=10)
    shell = client.invoke_shell()
    expect_prompt(shell, ("#", ">"))
    send_cmd(shell, "enable", patterns=("assword:", "#"))
    send_cmd(shell, PASSWORD, patterns=("#",))
    send_cmd(shell, "terminal length 0", patterns=("#",))
    return client, shell

def read_file_lines(filename):
    """Reads lines from a text file, stripping whitespace."""
    try:
        with open(filename, "r") as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"Error: The file '{filename}' was not found.")
        return []

def blackhole_unused_ports(shell, target_ip, config_commands):
    print(f"\n[HOP] ssh to {target_ip}")
    out = send_cmd(shell, f"ssh -l {USERNAME} {target_ip}",
                   patterns=("Destination", "(yes/no)?", "assword:", "%", "#", ">"),
                   timeout=15)

    if "(yes/no)?" in out or "yes/no" in out:
        out = send_cmd(shell, "yes", patterns=("assword:", "%", "#", ">"), timeout=15)
    if "assword:" in out:
        out = send_cmd(shell, PASSWORD, patterns=("%", "#", ">"), timeout=15)
    if out.strip().endswith(">"):
        send_cmd(shell, "enable", patterns=("assword:", "#"), timeout=15)
        send_cmd(shell, PASSWORD, patterns=("#",), timeout=15)
    
    send_cmd(shell, "terminal length 0", patterns=("#",), timeout=5)
    print(f"[CONNECTED] at {target_ip}#")

    print("[INFO] Gathering interface data...")
    interface_output = send_cmd(shell, 'show interfaces status', patterns=("#",))

    # Corrected regex to capture the entire interface name as a single group.
    # The parentheses around `(Gi|Te)\d+(/\d+){1,2}` now make it a single match group.
    notconnect_ports = re.findall(r'^((Gi|Te)\d+(/\d+){1,2})\s{2,}notconnect\s+.*$', interface_output, re.MULTILINE)

    if not notconnect_ports:
        print("[INFO] No unused ports found that meet the criteria.")
        send_cmd(shell, "exit", patterns=("#", ">"), timeout=5)
        print(f"[EXITED] back to aggregation switch prompt")
        return

    print(f"[INFO] Found {len(notconnect_ports)} unused ports:")
    
    send_cmd(shell, "configure terminal", patterns=("(config)#",), timeout=10)

    for port in notconnect_ports:
        port_name = port[0] # Correctly extracts the full port name from the match
        print(f"[CONFIG] Blackholing port: {port_name}")
        send_cmd(shell, f"interface {port_name}", patterns=("(config-if)#",), timeout=5)
        
        for cmd in config_commands:
            send_cmd(shell, cmd, patterns=("(config-if)#",), timeout=5)
        
        send_cmd(shell, "exit", patterns=("(config)#",), timeout=5)

    print("[CONFIG] Saving with 'do write'")
    send_cmd(shell, "do write", patterns=("(config)#", "#"), timeout=20)

    send_cmd(shell, "end", patterns=("#",), timeout=5)
    send_cmd(shell, "exit", patterns=("#", ">"), timeout=5)
    print(f"[EXITED] back to aggregation switch prompt")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 blackhole_ports.py <devices_file> <config_file>")
        sys.exit(1)

    devices_file = sys.argv[1]
    config_file = sys.argv[2]
    
    target_ips = read_file_lines(devices_file)
    config_cmds = read_file_lines(config_file)

    if not target_ips or not config_cmds:
        print("Script terminated. Please ensure both files are present and not empty.")
        sys.exit(1)

    client, shell = connect_to_agg()

    for target in target_ips:
        try:
            print(f"\n=== Processing {target} ===")
            blackhole_unused_ports(shell, target, config_cmds)
            print(f"[SUCCESS] Processed {target} successfully.")
        except Exception as e:
            print(f"[ERROR] Failed to process {target}: {e}")
    
    client.close()

    print("\nAll configurations completed.")
