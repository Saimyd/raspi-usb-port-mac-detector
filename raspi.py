#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Raspberry Pi USB Port MAC Detector
A comprehensive system for detecting Bluetooth dongles and RFID cards

Author: Pollux Labs
Website: en.polluxlabs.net
License: MIT
"""

import os
import re
import subprocess
import time
import logging
import threading
from datetime import datetime
from rc522_spi_library import RC522SPILibrary, StatusCodes
import requests

# ANSI color codes
RED     = '\033[91m'
GREEN   = '\033[92m'
YELLOW  = '\033[93m'
BLUE    = '\033[94m'
MAGENTA = '\033[95m'
CYAN    = '\033[96m'
BOLD    = '\033[1m'
RESET   = '\033[0m'

# Port mapping from raw names to numerical ports (pluggedPort will be sent as numerical value)
PORT_NUM_TABLE = {
    "3-1.1.1": 1,      # top left
    "3-1.2": 2,        # top
    "3-1.3": 3,        # top right
    "3-1.1.2": 4,      # left
    "3-1.1.3": 5,      # center
    "3-1.4": 6,        # right
    "3-1.1.4": 7,      # bottom left
    "3-2": 8,          # bottom
    "1-1": 9           # bottom right
}

# MAC addresses to numerical location IDs
MAC_NUM_TABLE = {
    "04:7F:0E:76:AF:41": 1,  # sun
    "04:7F:0E:76:B5:B1": 2,  # pharmacy
    "04:7F:0E:76:B4:72": 3,  # hospital
    "04:7F:0E:76:B6:9A": 4,  # library
    "04:7F:0E:76:B5:50": 5,  # school
    "04:7F:0E:76:AD:99": 6,  # home
    "04:7F:0E:76:AF:2C": 7,  # health center
    "00:1A:7D:DA:71:13": 8,  # wrong
    "04:7F:0E:76:B6:B6": 9,  # ant nest south direction
    "04:7F:0E:76:B6:7B": 10  # tree north direction
}

# Log file settings
log_dir = os.path.expanduser("~/usb_detector_logs")
os.makedirs(log_dir, exist_ok=True)
log_file = os.path.join(log_dir, f"usb_detector_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.FileHandler(log_file, encoding='utf-8'), logging.StreamHandler()]
)

HCI_WAIT_TIME = 3
MAC_RETRY_WAIT = 2
MAX_RETRIES = 5

entry_event = threading.Event()
card_status = {}
known_bt_macs = {}

# Global user ID information and last read card UID
current_user_id = ""
last_card_uid = ""

API_LOGIN_URL = "http://event7.net/api/loginrequest"
API_PROCESS_URL = "http://event7.net/api/processrequest"

def send_to_api(url, data):
    try:
        response = requests.post(url, json=data, timeout=5)
        if response.status_code == 200:
            print(f"{GREEN}Successfully sent to API!{RESET}")
        else:
            print(f"{RED}API Error: {response.status_code} - {response.text}{RESET}")
    except Exception as e:
        print(f"{RED}API connection error: {e}{RESET}")

def send_login_request(user_id, device_code, login_flag):
    data = {
        "userId": user_id,
        "deviceCode": device_code,
        "loginFlag": login_flag
    }
    send_to_api(API_LOGIN_URL, data)

def send_process_request(user_id, location_id, plugged_port_num, process_type):
    data = {
        "userId": user_id,
        "deviceCode": "TLaptop",
        "componentId": location_id,    # artık sayısal lokasyon ID'si gönderiliyor
        "pluggedPort": plugged_port_num,  # sayısal port numarası
        "processType": process_type
    }
    send_to_api(API_PROCESS_URL, data)

def read_sys_attr(file_path):
    if os.path.exists(file_path):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return f.read().strip()
        except Exception:
            logging.debug(f"Error reading file: {file_path}")
    return ""

def get_sys_usb_info():
    devices = {}
    base_path = "/sys/bus/usb/devices"
    if not os.path.exists(base_path):
        logging.error(f"{base_path} directory not found.")
        return devices

    for dev_name in os.listdir(base_path):
        dev_full_path = os.path.join(base_path, dev_name)
        if not os.path.isdir(dev_full_path) or ":" in dev_name:
            continue
        try:
            dev_attrs = {
                "devpath": read_sys_attr(os.path.join(dev_full_path, "devpath")),
                "product": read_sys_attr(os.path.join(dev_full_path, "product")),
                "idVendor": read_sys_attr(os.path.join(dev_full_path, "idVendor")),
                "idProduct": read_sys_attr(os.path.join(dev_full_path, "idProduct")),
                "manufacturer": read_sys_attr(os.path.join(dev_full_path, "manufacturer")),
                "serial": read_sys_attr(os.path.join(dev_full_path, "serial")),
                "bDeviceClass": read_sys_attr(os.path.join(dev_full_path, "bDeviceClass")),
                "bDeviceSubClass": read_sys_attr(os.path.join(dev_full_path, "bDeviceSubClass")),
                "bDeviceProtocol": read_sys_attr(os.path.join(dev_full_path, "bDeviceProtocol")),
                "sys_path": dev_full_path,
                "port": dev_name,
                "interfaces": []
            }

            for entry in os.listdir(dev_full_path):
                if re.match(rf"^{re.escape(dev_name)}:\d+\.\d+", entry):
                    if_path = os.path.join(dev_full_path, entry)
                    if os.path.isdir(if_path):
                        dev_attrs["interfaces"].append({
                            "bInterfaceClass": read_sys_attr(os.path.join(if_path, "bInterfaceClass")),
                            "bInterfaceSubClass": read_sys_attr(os.path.join(if_path, "bInterfaceSubClass")),
                            "bInterfaceProtocol": read_sys_attr(os.path.join(if_path, "bInterfaceProtocol")),
                            "interface_number": read_sys_attr(os.path.join(if_path, "bInterfaceNumber"))
                        })
            devices[dev_name] = dev_attrs
        except Exception as e:
            logging.warning(f"Error (dev: {dev_name}): {e}")
    return devices

def get_active_bluetooth_interfaces():
    interfaces = []
    try:
        result = subprocess.run(['hcitool', 'dev'], capture_output=True, text=True)
        if result.returncode == 0 and result.stdout:
            for line in result.stdout.strip().split('\n')[1:]:
                match = re.search(r'\s*(hci\d+)\s+([0-9A-Fa-f:]{17})', line)
                if match:
                    interfaces.append({"name": match.group(1), "mac": match.group(2).upper()})

        if not interfaces:
            result = subprocess.run(['bluetoothctl', 'list'], capture_output=True, text=True)
            for line in result.stdout.strip().split('\n'):
                match = re.search(r'Controller\s+([0-9A-Fa-f:]{17})\s+(\S+)', line)
                if match:
                    mac = match.group(1).upper()
                    hci_name = "N/A"
                    for hci_dev in os.listdir("/sys/class/bluetooth"):
                        addr_path = os.path.join("/sys/class/bluetooth", hci_dev, "address")
                        if os.path.exists(addr_path) and read_sys_attr(addr_path).upper() == mac:
                            hci_name = hci_dev
                            break
                    interfaces.append({"name": hci_name, "mac": mac})
    except Exception as e:
        logging.error(f"Could not list Bluetooth interfaces: {e}")
    return interfaces

def check_bluetooth_device(info):
    if not info:
        return False
    if (info.get("bDeviceClass") == "e0" and info.get("bDeviceSubClass") == "01" and info.get("bDeviceProtocol") == "01"):
        return True
    for if_attr in info.get("interfaces", []):
        if (if_attr.get("bInterfaceClass") == "e0" and if_attr.get("bInterfaceSubClass") == "01" and if_attr.get("bInterfaceProtocol") == "01"):
            return True
    if info.get("bDeviceClass") == "ff":
        for if_attr in info.get("interfaces", []):
            if (if_attr.get("bInterfaceClass") == "e0" and if_attr.get("bInterfaceSubClass") == "01" and if_attr.get("bInterfaceProtocol") == "01"):
                return True

    product = info.get("product", "").lower()
    manufacturer = info.get("manufacturer", "").lower()
    if "bluetooth" in product or "bt" in product or "bluetooth" in manufacturer:
        return True

    vendor = info.get("idVendor", "").lower()
    product_id = info.get("idProduct", "").lower()

    known = [
        {"vendor": "0a12", "product": "0001"},
        {"vendor": "0a5c", "product": "21e8"},
        {"vendor": "0cf3", "product": "e300"},
        {"vendor": "0b05", "product": "17cb"},
    ]
    for combo in known:
        if vendor == combo["vendor"] and product_id == combo["product"]:
            return True
    return False

def send_all_active_dongles(user_id):
    current_devices = get_sys_usb_info()
    active_hcis = get_active_bluetooth_interfaces()
    prev_macs = {iface['mac'] for iface in active_hcis}

    for dev_name, info in current_devices.items():
        if check_bluetooth_device(info):
            port_raw = info.get("port", "N/A")
            plugged_port_num = PORT_NUM_TABLE.get(port_raw, 0)  # Sayısal port numarası, 0 bilinmeyen
            mac_address = known_bt_macs.get(port_raw, None)
            if not mac_address:
                # Try to get MAC address from USB device
                for hci in active_hcis:
                    mac_upper = hci["mac"].upper()
                    if mac_upper in MAC_NUM_TABLE:
                        mac_address = mac_upper
                        break
            location_id = MAC_NUM_TABLE.get(mac_address, 0)  # Sayısal lokasyon ID'si, 0 bilinmeyen

            print(f"{CYAN}Active Dongle - Port: {plugged_port_num}, Location ID: {location_id}{RESET}")

            send_process_request(user_id=user_id, location_id=location_id, plugged_port_num=plugged_port_num, process_type=1)

def monitor_usb_ports():
    global known_bt_macs, current_user_id, last_card_uid
    print(f"\n{BOLD}{BLUE}{'*'*60}")
    print("* Raspberry Pi USB Bluetooth Dongle Port Detector *".center(60))
    print(f"* Log file: {log_file}".ljust(59) + "*")
    print("* Press Ctrl+C to exit".ljust(59) + "*")
    print(f"{'*'*60}{RESET}\n")

    known_devices = get_sys_usb_info()
    active_hcis = get_active_bluetooth_interfaces()
    known_bt_macs = {}

    try:
        while True:
            if not entry_event.is_set():
                time.sleep(1)
                continue
            time.sleep(2)
            current_devices = get_sys_usb_info()
            current_hcis = get_active_bluetooth_interfaces()

            added = {k: v for k, v in current_devices.items() if k not in known_devices}
            removed = {k: v for k, v in known_devices.items() if k not in current_devices}

            prev_macs = {iface['mac'] for iface in active_hcis}

            for dev_name, info in added.items():
                if check_bluetooth_device(info):
                    port_raw = info.get("port", "N/A")
                    plugged_port_num = PORT_NUM_TABLE.get(port_raw, 0)
                    print(f"{GREEN}{BOLD}\n{'='*60}")
                    print(" NEW BLUETOOTH DONGLE DETECTED ".center(60, '='))
                    time.sleep(HCI_WAIT_TIME)

                    mac_address = "Not Detected"
                    for attempt in range(MAX_RETRIES):
                        new_hcis = get_active_bluetooth_interfaces()
                        new_macs = [h['mac'] for h in new_hcis if h['mac'] not in prev_macs]
                        if new_macs:
                            mac_address = new_macs[0]
                            known_bt_macs[port_raw] = mac_address
                            break
                        time.sleep(MAC_RETRY_WAIT)

                    location_id = MAC_NUM_TABLE.get(mac_address, 0)
                    plugged_port_num = plugged_port_num

                    print(f"{CYAN}Port ID: {plugged_port_num}{RESET}")
                    print(f"{CYAN}MAC: {mac_address}{RESET}")
                    print(f"{CYAN}Yer ID: {location_id}{RESET}")
                    print(f"{GREEN}{'='*60}{RESET}")

                    # userId boş ise last_card_uid'yi kullan
                    user_id_to_send = current_user_id if current_user_id else last_card_uid

                    send_process_request(
                        user_id=user_id_to_send,
                        location_id=location_id,
                        plugged_port_num=plugged_port_num,
                        process_type=1
                    )

            for dev_name, info in removed.items():
                if check_bluetooth_device(info):
                    port_raw = info.get("port", "N/A")
                    plugged_port_num = PORT_NUM_TABLE.get(port_raw, 0)
                    mac_address = known_bt_macs.pop(port_raw, "Unknown MAC")
                    location_id = MAC_NUM_TABLE.get(mac_address, 0)
                    print(f"{RED}{BOLD}\n{'-'*60}")
                    print(" BLUETOOTH DONGLE REMOVED ".center(60, '-'))
                    print(f"{RESET}{CYAN}Port ID: {plugged_port_num}{RESET}")
                    print(f"{RESET}{CYAN}MAC: {mac_address}{RESET}")
                    print(f"{RESET}{CYAN}Yer ID: {location_id}{RESET}")
                    print(f"{RED}{'-'*60}{RESET}")

                    user_id_to_send = current_user_id if current_user_id else last_card_uid

                    send_process_request(
                        user_id=user_id_to_send,
                        location_id=location_id,
                        plugged_port_num=plugged_port_num,
                        process_type=2
                    )

            known_devices = current_devices
            active_hcis = get_active_bluetooth_interfaces()

    except KeyboardInterrupt:
        print(f"\n{YELLOW}{BOLD}USB monitoring terminated.{RESET}")

def rfid_main():
    global card_status, current_user_id, last_card_uid
    print(f"{MAGENTA}{BOLD}RFID Card Reader Started...{RESET}")
    reader = None

    try:
        reader = RC522SPILibrary(rst_pin=22)

        while True:
            status, _ = reader.request()
            if status == StatusCodes.OK:
                status, uid = reader.anticoll()
                if status == StatusCodes.OK:
                    uid_str = ":".join([f"{i:02X}" for i in uid])
                    now = time.time()
                    info = card_status.get(uid_str)

                    if info is None:
                        # First entry
                        print(f"{GREEN}LOGIN - UID: {uid_str}{RESET}")
                        card_status[uid_str] = {"last_time": now, "state": "in"}
                        entry_event.set()

                        current_user_id = uid_str
                        last_card_uid = uid_str

                        send_login_request(user_id=uid_str, device_code="TLaptop", login_flag=1)

                        # After RFID reading, associate active dongles with user and send to API
                        send_all_active_dongles(uid_str)

                    else:
                        elapsed = now - info["last_time"]

                        if info["state"] == "in" and elapsed >= 30:
                            # Logout
                            print(f"{RED}LOGOUT - UID: {uid_str}{RESET}")
                            card_status[uid_str] = {"last_time": now, "state": "out"}

                            # Clear entry_event if no other login exists
                            if not any(v["state"] == "in" for v in card_status.values()):
                                entry_event.clear()

                            current_user_id = ""
                            last_card_uid = uid_str

                            send_login_request(user_id=uid_str, device_code="TLaptop", login_flag=2)

                        elif info["state"] == "out" and elapsed >= 30:
                            # Re-login
                            print(f"{GREEN}LOGIN - UID: {uid_str}{RESET}")
                            card_status[uid_str] = {"last_time": now, "state": "in"}
                            entry_event.set()

                            current_user_id = uid_str
                            last_card_uid = uid_str

                            send_login_request(user_id=uid_str, device_code="TLaptop", login_flag=1)

                            send_all_active_dongles(uid_str)

                        else:
                            # Too frequent reading is prevented
                            pass

            time.sleep(0.1)

    except KeyboardInterrupt:
        print(f"\n{YELLOW}{BOLD}RFID reader stopped.{RESET}")
    except Exception as e:
        logging.error(f"RFID ERROR: {e}")
    finally:
        if reader:
            reader.cleanup()
            print("RC522 resources cleaned up.")

if __name__ == "__main__":
    try:
        t1 = threading.Thread(target=monitor_usb_ports, daemon=True)
        t2 = threading.Thread(target=rfid_main, daemon=True)

        t1.start()
        t2.start()

        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print(f"\n{YELLOW}{BOLD}Program terminated.{RESET}")
