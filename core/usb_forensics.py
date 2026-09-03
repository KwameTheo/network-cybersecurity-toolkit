"""
USB Device History & Digital Forensics Engine
Extracts historical USB storage device artifacts from the Windows Registry (USBSTOR),
identifies hardware serial numbers, VID/PID, manufacturers, and audits live connected peripherals.
"""

import os
import platform
import re
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional
import psutil

if platform.system() == "Windows":
    import winreg
else:
    winreg = None

from utils.logger import get_logger
from utils.subprocess_runner import run_powershell

logger = get_logger()

# Known USB Vendor ID Dictionary
COMMON_USB_VIDS: Dict[str, str] = {
    "0951": "Kingston Technology",
    "0781": "SanDisk Corp.",
    "058F": "Alcor Micro (Flash Controller)",
    "13FE": "Phison Electronics",
    "04E8": "Samsung Electronics",
    "054C": "Sony Corp.",
    "0930": "Toshiba Corp.",
    "1058": "Western Digital",
    "0BC2": "Seagate Technology",
    "046D": "Logitech, Inc.",
    "04F2": "Chicony Electronics (Webcam)",
    "1FD2": "Generic USB Peripheral",
    "8087": "Intel Corp.",
    "18D1": "Google Inc. (Android Device)",
    "05AC": "Apple, Inc.",
    "17EF": "Lenovo",
    "03F0": "HP Inc.",
}


@dataclass
class USBStorageDeviceRecord:
    device_name: str
    device_type: str  # e.g., "Disk", "Flash", "CardReader"
    serial_number: str
    vendor_id: str
    product_id: str
    manufacturer: str
    is_connected: bool
    mount_point: Optional[str]
    registry_path: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class USBForensicsSummary:
    total_historical_storage_devices: int
    currently_connected_storage_devices: int
    currently_connected_usb_peripherals: int
    storage_devices: List[USBStorageDeviceRecord]
    connected_peripherals: List[Dict[str, str]]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# =========================================================================
# REGISTRY FORENSICS PARSING (USBSTOR)
# =========================================================================

def parse_friendly_manufacturer(dev_type_str: str, raw_mfg: str) -> str:
    """Extracts a readable brand name from raw registry strings."""
    upper_str = f"{dev_type_str} {raw_mfg}".upper()
    if "KINGSTON" in upper_str:
        return "Kingston Technology"
    if "SANDISK" in upper_str:
        return "SanDisk"
    if "TOSHIBA" in upper_str:
        return "Toshiba"
    if "SAMSUNG" in upper_str:
        return "Samsung"
    if "SONY" in upper_str:
        return "Sony"
    if "NOKIA" in upper_str:
        return "Nokia Mobile"
    if "WESTERN DIGITAL" in upper_str or "WD" in upper_str:
        return "Western Digital"
    if "SEAGATE" in upper_str:
        return "Seagate"
    if "UDISK" in upper_str or "GENERIC" in upper_str or "FLASH DISK" in upper_str:
        return "Generic USB Flash Drive"

    # Clean raw string
    clean = re.sub(r"@[^;]+;", "", raw_mfg).strip()
    return clean or "Standard USB Storage Device"


def get_usb_storage_history() -> List[USBStorageDeviceRecord]:
    """
    Scans HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR to enumerate
    every USB storage device ever connected to this Windows system.
    """
    if platform.system() != "Windows" or winreg is None:
        return []

    records: List[USBStorageDeviceRecord] = []
    key_root = r"SYSTEM\CurrentControlSet\Enum\USBSTOR"

    # Identify currently mounted removable drive mountpoints
    removable_mounts = []
    try:
        for p in psutil.disk_partitions(all=True):
            if "removable" in p.opts.lower() or "cdrom" in p.opts.lower():
                removable_mounts.append(p.mountpoint)
    except Exception:
        pass

    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_root) as root_key:
            num_subkeys, _, _ = winreg.QueryInfoKey(root_key)
            for i in range(num_subkeys):
                dev_sub_name = winreg.EnumKey(root_key, i)
                dev_path = f"{key_root}\\{dev_sub_name}"

                # Parse device type category from subkey e.g. "Disk&Ven_Kingston&Prod_DataTraveler"
                dev_type = "Disk"
                if "CdRom" in dev_sub_name:
                    dev_type = "Optical Drive"
                elif "Card" in dev_sub_name:
                    dev_type = "Card Reader"
                elif "Flash" in dev_sub_name or "Disk" in dev_sub_name:
                    dev_type = "USB Flash Drive"

                try:
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, dev_path) as dev_key:
                        num_instances, _, _ = winreg.QueryInfoKey(dev_key)
                        for j in range(num_instances):
                            instance_id = winreg.EnumKey(dev_key, j)
                            inst_path = f"{dev_path}\\{instance_id}"

                            try:
                                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, inst_path) as inst_key:
                                    friendly_name = ""
                                    try:
                                        friendly_name, _ = winreg.QueryValueEx(inst_key, "FriendlyName")
                                    except FileNotFoundError:
                                        pass

                                    raw_mfg = ""
                                    try:
                                        raw_mfg, _ = winreg.QueryValueEx(inst_key, "Mfg")
                                    except FileNotFoundError:
                                        pass

                                    clean_name = friendly_name or dev_sub_name
                                    clean_mfg = parse_friendly_manufacturer(dev_sub_name, raw_mfg)

                                    # Clean serial number (strip &0 or instance tail)
                                    clean_serial = instance_id.split("&")[0] if "&" in instance_id else instance_id

                                    # Check if hardware VID/PID in string
                                    vid_match = re.search(r"VID_([0-9A-Fa-f]{4})", dev_sub_name, re.IGNORECASE)
                                    pid_match = re.search(r"PID_([0-9A-Fa-f]{4})", dev_sub_name, re.IGNORECASE)
                                    vid_str = vid_match.group(1).upper() if vid_match else "--"
                                    pid_str = pid_match.group(1).upper() if pid_match else "--"

                                    if vid_str in COMMON_USB_VIDS and clean_mfg == "Standard USB Storage Device":
                                        clean_mfg = COMMON_USB_VIDS[vid_str]

                                    records.append(USBStorageDeviceRecord(
                                        device_name=clean_name,
                                        device_type=dev_type,
                                        serial_number=clean_serial or instance_id,
                                        vendor_id=vid_str,
                                        product_id=pid_str,
                                        manufacturer=clean_mfg,
                                        is_connected=False,  # Evaluated below
                                        mount_point=None,
                                        registry_path=inst_path
                                    ))
                            except Exception:
                                continue
                except Exception:
                    continue

        logger.info(f"Discovered {len(records)} historical USB storage device artifacts in registry.")
        return records
    except Exception as e:
        logger.error(f"Failed to query USBSTOR registry key: {e}", exc_info=True)
        return []


def get_connected_usb_peripherals() -> List[Dict[str, str]]:
    """
    Queries live active USB devices via PowerShell Get-PnpDevice.
    """
    if platform.system() != "Windows":
        return []

    cmd = "Get-PnpDevice -Class USB -Status OK | Select-Object -Property FriendlyName, InstanceId, Status | ConvertTo-Json"
    res = run_powershell(cmd)

    peripherals: List[Dict[str, str]] = []
    if not res.success or not res.stdout:
        return peripherals

    import json
    try:
        data = json.loads(res.stdout)
        if isinstance(data, dict):
            data = [data]

        for item in data:
            name = item.get("FriendlyName") or "Unknown USB Device"
            inst = item.get("InstanceId") or ""
            status = item.get("Status") or "OK"

            # Parse VID/PID
            vid_match = re.search(r"VID_([0-9A-Fa-f]{4})", inst, re.IGNORECASE)
            pid_match = re.search(r"PID_([0-9A-Fa-f]{4})", inst, re.IGNORECASE)
            vid = vid_match.group(1).upper() if vid_match else "--"
            pid = pid_match.group(1).upper() if pid_match else "--"
            vendor = COMMON_USB_VIDS.get(vid, "Generic Device")

            peripherals.append({
                "name": name,
                "instance_id": inst,
                "vendor_id": vid,
                "product_id": pid,
                "vendor": vendor,
                "status": status
            })
    except Exception as e:
        logger.warning(f"Failed to parse PnP USB devices JSON: {e}")

    return peripherals


def run_usb_forensic_audit() -> USBForensicsSummary:
    """
    Compiles complete USB forensic audit across historical storage artifacts and live peripherals.
    """
    storage_history = get_usb_storage_history()
    live_peripherals = get_connected_usb_peripherals()

    connected_storage_count = sum(1 for s in storage_history if s.is_connected)

    return USBForensicsSummary(
        total_historical_storage_devices=len(storage_history),
        currently_connected_storage_devices=connected_storage_count,
        currently_connected_usb_peripherals=len(live_peripherals),
        storage_devices=storage_history,
        connected_peripherals=live_peripherals
    )
