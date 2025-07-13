import argparse
import logging
import threading
import subprocess
import tempfile
import time
import os
import re
import signal
from pathlib import Path
from typing import Optional
import pty
import subprocess
import select
import sys

def kill_conflicting_processes():
    subprocess.run(["sudo", "airmon-ng", "check", "kill"], capture_output=True, text=True, check=True)

def enable_monitor_mode(iface: str) -> str:
    """
    Enable monitor mode on *iface* using airmon‑ng and
    return the resulting monitor‑mode interface name.

    If the interface is already in monitor mode (ends with 'mon'), it is returned unchanged.
    """
    if iface.endswith("mon"):
        return iface  # already monitor mode

    # airmon‑ng outputs something like:  (monitor mode enabled on wlan0mon)
    cmd = ["sudo", "airmon-ng", "start", iface]
    print("[*] Enabling monitor mode:", " ".join(cmd))
    result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    print(result);

def find_bssid(essid: str, iface: str = "wlan0mon", timeout: Optional[int] = None) -> Optional[str]:
    master_fd, slave_fd = pty.openpty()

    process = subprocess.Popen(
        ["sudo", "airodump-ng", iface],
        stdout=slave_fd,
        stderr=subprocess.STDOUT,
        text=False  # we decode manually
    )

    os.close(slave_fd)

    buffer = ""
    start_time = time.time()

    try:
        while process.poll() is None:
            # check whether we've timed out
            if timeout and (time.time() - start_time) > timeout:
                print("\nTimeout reached. Stopping scan.")
                break

            # if we get here, we haven't timed out
            ready, _, _ = select.select([master_fd], [], [], 0.5)
            if ready:
                chunk = os.read(master_fd, 4096).decode(errors="replace")
                buffer += chunk

                # Split buffer into lines and process them
                lines = buffer.splitlines()

                for line in lines:
                    if essid in line:
                        parts = line.split()
                        # Heuristically look for BSSID
                        if len(parts) >= 2:
                            bssid_candidate = parts[0]
                            if ":" in bssid_candidate and len(bssid_candidate) == 17:
                                print(f"\nFound ESSID '{essid}' with BSSID: {bssid_candidate}")
                                return bssid_candidate
                # Prevent buffer from growing too big
                if len(buffer) > 100000:
                    buffer = buffer[-10000:]
    except KeyboardInterrupt:
        print("\nInterrupted. Exiting...")
    finally:
        try:
            process.terminate()
        except Exception:
            pass
        process.wait()
        os.close(master_fd)

    print("ESSID not found.")
    return None

def send_deauth_packets(bssid: str):

    return;

def main():
    # Create argument parser
    parser = argparse.ArgumentParser(
        description="Wi-Fi target capture tool using airodump-ng"
    )

    # Add named (optional-looking but required) arguments
    parser.add_argument("--target", required=True, help="Target network ESSID (e.g., 'MyWiFi')")
    parser.add_argument("--interface", required=True, help="Wireless interface in monitor mode (e.g., wlan0mon)")
    parser.add_argument("--capfile", required=True, help="Output capture file prefix (e.g., 'output-file')")

    # Parse the arguments
    args = parser.parse_args()

    # Log what we're doing
    logging.info("Target: %s", args.target)
    logging.info("Interface: %s", args.interface)
    logging.info("Capture File: %s", args.capfile)

    kill_conflicting_processes()
    enable_monitor_mode(args.interface)
    bssid = find_bssid(args.target, args.interface, 20)
    
    if bssid:
        print(f"✓ Got BSSID {bssid}; now I can continue…")
        send_deauth_packets(bssid)
    else:
        print("✗ Network not seen — decide what to do next.")

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='[%(asctime)s] [%(levelname)s] %(message)s',
        datefmt='%H:%M:%S'
    )
    try:
        main()
    except KeyboardInterrupt:
        logging.info("User interrupted. Exiting …")
    except Exception as e:
        logging.error("Error: %s", e)
