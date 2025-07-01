#!/usr/bin/env python3
import requests
import xml.etree.ElementTree as ET
import json
import subprocess
import os
import time
from datetime import datetime

UCS_IP = "192.168.1.35"
USERNAME = "admin"
PASSWORD = "password"
ZABBIX_SERVER = "192.168.1.39"
ZABBIX_HOST = "UCS-TEST"
ZABBIX_SENDER = "/opt/homebrew/bin/zabbix_sender"
CACHE_FILE = "/tmp/ucs_fault_cache.json"
CHASSIS_CACHE_FILE = "/tmp/ucs_chassis_cache.json"
TMP_DIR = "/tmp/ucs_zabbix"
os.makedirs(TMP_DIR, exist_ok=True)

SEVERITY_KEYS = {
    "critical": "ucs.fault.critical",
    "major": "ucs.fault.major",
    "minor": "ucs.fault.minor",
    "warning": "ucs.fault.warning",
    "info": "ucs.fault.info"
}

DISCOVERY_KEYS = {
    "critical": "ucs.fault.discovery.critical",
    "major": "ucs.fault.discovery.major",
    "minor": "ucs.fault.discovery.minor",
    "warning": "ucs.fault.discovery.warning",
    "info": "ucs.fault.discovery.info"
}

# Chassis monitoring için yeni sabitler
CHASSIS_DISCOVERY_KEY = "ucs.chassis.discovery"
CHASSIS_KEYS = {
    "power_state": "ucs.chassis.power_state",
    "thermal_state": "ucs.chassis.thermal_state",
    "overall_status": "ucs.chassis.overall_status",
    "oper_state": "ucs.chassis.oper_state"
}

# Blade monitoring için sabitler
BLADE_DISCOVERY_KEY = "ucs.blade.discovery"
BLADE_CACHE_FILE = "/tmp/ucs_blade_cache.json"
BLADE_KEYS = {
    "power_state": "ucs.blade.power_state",
    "oper_state": "ucs.blade.oper_state",
    "operability": "ucs.blade.operability",
    "presence": "ucs.blade.presence"
}

# Fabric Interconnect monitoring için sabitler
FI_DISCOVERY_KEY = "ucs.fabric_interconnect.discovery"
FI_CACHE_FILE = "/tmp/ucs_fi_cache.json"
FI_KEYS = {
    "operability": "ucs.fabric_interconnect.operability",
    "thermal": "ucs.fabric_interconnect.thermal",
    "memory_usage": "ucs.fabric_interconnect.memory_usage",
    "fault_count": "ucs.fabric_interconnect.fault_count"
}

# Port monitoring için sabitler
PORT_DISCOVERY_KEY = "ucs.port.discovery"
PORT_CACHE_FILE = "/tmp/ucs_port_cache.json"
PORT_KEYS = {
    "admin_state": "ucs.port.admin_state",
    "oper_state": "ucs.port.oper_state",
    "if_role": "ucs.port.if_role"
}

# Server Interface monitoring için sabitler
SERVER_IF_DISCOVERY_KEY = "ucs.server_interface.discovery"
SERVER_IF_CACHE_FILE = "/tmp/ucs_server_if_cache.json"
SERVER_IF_KEYS = {
    "oper_state": "ucs.server_interface.oper_state",
    "admin_state": "ucs.server_interface.admin_state"
}

requests.packages.urllib3.disable_warnings()

def log(msg):
    print(f"[{datetime.now().strftime('%F %T')}] {msg}")

def login_ucs():
    url = f"https://{UCS_IP}/nuova"
    payload = f'<aaaLogin inName="{USERNAME}" inPassword="{PASSWORD}"/>'
    r = requests.post(url, data=payload, verify=False)
    r.raise_for_status()
    root = ET.fromstring(r.content)
    return root.attrib["outCookie"]

def get_faults(cookie):
    url = f"https://{UCS_IP}/nuova"
    payload = f'<configResolveClass cookie="{cookie}" classId="faultInst" inHierarchical="false"/>'
    r = requests.post(url, data=payload, verify=False)
    r.raise_for_status()
    root = ET.fromstring(r.content)
    return root.findall(".//faultInst")

def get_chassis(cookie):
    """UCS'den chassis bilgilerini alır"""
    url = f"https://{UCS_IP}/nuova"
    payload = f'<configResolveClass cookie="{cookie}" classId="equipmentChassis" inHierarchical="false"/>'
    r = requests.post(url, data=payload, verify=False)
    r.raise_for_status()
    root = ET.fromstring(r.content)
    return root.findall(".//equipmentChassis")

def get_blades(cookie):
    """UCS'den blade bilgilerini alır"""
    url = f"https://{UCS_IP}/nuova"
    payload = f'<configResolveClass cookie="{cookie}" classId="computeBlade" inHierarchical="false"/>'
    r = requests.post(url, data=payload, verify=False)
    r.raise_for_status()
    root = ET.fromstring(r.content)
    return root.findall(".//computeBlade")

def get_fabric_interconnects(cookie):
    """UCS'den fabric interconnect bilgilerini alır"""
    url = f"https://{UCS_IP}/nuova"
    payload = f'<configResolveClass cookie="{cookie}" classId="networkElement" inHierarchical="false"/>'
    r = requests.post(url, data=payload, verify=False)
    r.raise_for_status()
    root = ET.fromstring(r.content)
    return root.findall(".//networkElement")

def get_ports(cookie):
    """UCS'den fabric interconnect port bilgilerini alır"""
    url = f"https://{UCS_IP}/nuova"
    payload = f'<configResolveClass cookie="{cookie}" classId="etherPIo" inHierarchical="false"/>'
    r = requests.post(url, data=payload, verify=False)
    r.raise_for_status()
    root = ET.fromstring(r.content)
    return root.findall(".//etherPIo")

def get_server_interfaces(cookie):
    """UCS'den server interface port bilgilerini alır"""
    url = f"https://{UCS_IP}/nuova"
    payload = f'<configResolveClass cookie="{cookie}" classId="etherServerIntFIo" inHierarchical="false"/>'
    r = requests.post(url, data=payload, verify=False)
    r.raise_for_status()
    root = ET.fromstring(r.content)
    return root.findall(".//etherServerIntFIo")

def load_cache():
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, "r") as f:
            return json.load(f)
    return {}

def save_cache(cache):
    with open(CACHE_FILE, "w") as f:
        json.dump(cache, f)

def load_chassis_cache():
    """Chassis cache'ini yükler"""
    if os.path.exists(CHASSIS_CACHE_FILE):
        with open(CHASSIS_CACHE_FILE, "r") as f:
            return json.load(f)
    return {}

def save_chassis_cache(cache):
    """Chassis cache'ini kaydeder"""
    with open(CHASSIS_CACHE_FILE, "w") as f:
        json.dump(cache, f)

def load_blade_cache():
    """Blade cache'ini yükler"""
    if os.path.exists(BLADE_CACHE_FILE):
        with open(BLADE_CACHE_FILE, "r") as f:
            return json.load(f)
    return {}

def save_blade_cache(cache):
    """Blade cache'ini kaydeder"""
    with open(BLADE_CACHE_FILE, "w") as f:
        json.dump(cache, f)

def load_fi_cache():
    """Fabric Interconnect cache'ini yükler"""
    if os.path.exists(FI_CACHE_FILE):
        with open(FI_CACHE_FILE, "r") as f:
            return json.load(f)
    return {}

def save_fi_cache(cache):
    """Fabric Interconnect cache'ini kaydeder"""
    with open(FI_CACHE_FILE, "w") as f:
        json.dump(cache, f)

def load_port_cache():
    """Port cache'ini yükler"""
    if os.path.exists(PORT_CACHE_FILE):
        with open(PORT_CACHE_FILE, "r") as f:
            return json.load(f)
    return {}

def save_port_cache(cache):
    """Port cache'ini kaydeder"""
    with open(PORT_CACHE_FILE, "w") as f:
        json.dump(cache, f)

def load_server_if_cache():
    """Server Interface cache'ini yükler"""
    if os.path.exists(SERVER_IF_CACHE_FILE):
        with open(SERVER_IF_CACHE_FILE, "r") as f:
            return json.load(f)
    return {}

def save_server_if_cache(cache):
    """Server Interface cache'ini kaydeder"""
    with open(SERVER_IF_CACHE_FILE, "w") as f:
        json.dump(cache, f)

def send_to_zabbix(file_path):
    cmd = [ZABBIX_SENDER, "-z", ZABBIX_SERVER, "-s", ZABBIX_HOST, "-i", file_path]
    result = subprocess.run(cmd, capture_output=True, text=True)
    log(f"[ZABBIX_SENDER]: {file_path}")
    log(result.stdout.strip())
    if result.returncode != 0:
        log(result.stderr.strip())

def send_discovery_only(discovery_data):
    for sev, data in discovery_data.items():
        disc_file = os.path.join(TMP_DIR, f"discovery_{sev}.txt")
        disc_json = json.dumps({"data": data}, ensure_ascii=False)
        with open(disc_file, "w", encoding="utf-8") as f:
            f.write(f"{ZABBIX_HOST} {DISCOVERY_KEYS[sev]} {disc_json}\n")
        send_to_zabbix(disc_file)

def send_items_only(item_lines):
    fault_file = os.path.join(TMP_DIR, "faults.txt")
    with open(fault_file, "w") as f:
        for line in item_lines:
            f.write(line.strip() + "\n")
    send_to_zabbix(fault_file)

def build_zabbix_data(faults, cache):
    current_ids = set()
    discovery_data = {sev: [] for sev in SEVERITY_KEYS}
    item_lines = []

    for f in faults:
        fid = f.attrib.get("id")
        sev = f.attrib.get("severity", "info").lower()
        if sev not in SEVERITY_KEYS:
            log(f"Skipping unknown severity: {sev} for fault ID {fid}")
            continue

        code = f.attrib.get("code", "")
        descr = f.attrib.get("descr", "")
        key = f"{SEVERITY_KEYS[sev]}[{fid}]"

        if fid not in cache:
            item_lines.append(f"{ZABBIX_HOST} {key} 0")  # dummy
            item_lines.append(f"{ZABBIX_HOST} {key} 1")  # real
        else:
            item_lines.append(f"{ZABBIX_HOST} {key} 1")

        discovery_data[sev].append({
            "{#FAULTID}": fid,
            "{#SEVERITY}": sev,
            "{#CODE}": code,
            "{#DESCR}": descr
        })

        current_ids.add(fid)
        cache[fid] = {"severity": sev}

    for fid in list(cache):
        if fid not in current_ids:
            sev = cache[fid]["severity"]
            key = f"{SEVERITY_KEYS[sev]}[{fid}]"
            item_lines.append(f"{ZABBIX_HOST} {key} 0")
            del cache[fid]

    return discovery_data, item_lines, cache

def build_chassis_zabbix_data(chassis_list, cache):
    """Chassis verilerini Zabbix formatına dönüştürür"""
    current_chassis = set()
    discovery_data = []
    item_lines = []

    for chassis in chassis_list:
        chassis_id = chassis.attrib.get("id", "")
        chassis_dn = chassis.attrib.get("dn", "")
        model = chassis.attrib.get("model", "")
        serial = chassis.attrib.get("serial", "")
        power_state = chassis.attrib.get("power", "unknown")
        thermal_state = chassis.attrib.get("thermal", "unknown")
        overall_status = chassis.attrib.get("operability", "unknown")
        oper_state = chassis.attrib.get("operState", "unknown")

        if not chassis_id:
            continue

        current_chassis.add(chassis_id)

        # Discovery data'sına ekleme
        discovery_data.append({
            "{#CHASSIS_ID}": chassis_id,
            "{#CHASSIS_DN}": chassis_dn,
            "{#CHASSIS_MODEL}": model,
            "{#CHASSIS_SERIAL}": serial,
            "{#CHASSIS_NAME}": f"{chassis_dn} ({model})"
        })

        # Item değerlerini hazırlama
        # Power state mapping (ok=1, off=0, unknown=2)
        power_value = 1 if power_state == "ok" else (0 if power_state == "off" else 2)
        
        # Thermal state mapping (ok=0, problem=1, unknown=2)
        thermal_value = 0 if thermal_state == "ok" else (1 if thermal_state in ["upper-non-critical", "upper-critical", "lower-non-critical", "lower-critical"] else 2)
        
        # Overall status mapping (operable=0, inoperable=1, degraded=2, unknown=3)
        status_mapping = {"operable": 0, "inoperable": 1, "degraded": 2}
        overall_value = status_mapping.get(overall_status, 3)
        
        # Oper state mapping (operable=1, inoperable=0, unknown=2)
        oper_value = 1 if oper_state == "operable" else (0 if oper_state == "inoperable" else 2)

        # Debug log
        log(f"Chassis {chassis_id}: power='{power_state}'→{power_value}, thermal='{thermal_state}'→{thermal_value}, status='{overall_status}'→{overall_value}, oper='{oper_state}'→{oper_value}")
        
        # Item'ları ekleme
        item_lines.append(f"{ZABBIX_HOST} {CHASSIS_KEYS['power_state']}[{chassis_id}] {power_value}")
        item_lines.append(f"{ZABBIX_HOST} {CHASSIS_KEYS['thermal_state']}[{chassis_id}] {thermal_value}")
        item_lines.append(f"{ZABBIX_HOST} {CHASSIS_KEYS['overall_status']}[{chassis_id}] {overall_value}")
        item_lines.append(f"{ZABBIX_HOST} {CHASSIS_KEYS['oper_state']}[{chassis_id}] {oper_value}")

        # Cache'e ekleme
        cache[chassis_id] = {
            "model": model,
            "serial": serial,
            "last_seen": datetime.now().isoformat()
        }

    # Artık mevcut olmayan chassis'leri cache'den temizleme
    for chassis_id in list(cache):
        if chassis_id not in current_chassis:
            del cache[chassis_id]

    return discovery_data, item_lines, cache

def send_chassis_discovery(discovery_data):
    """Chassis discovery verilerini Zabbix'e gönderir"""
    disc_file = os.path.join(TMP_DIR, "chassis_discovery.txt")
    disc_json = json.dumps({"data": discovery_data}, ensure_ascii=False)
    with open(disc_file, "w", encoding="utf-8") as f:
        f.write(f"{ZABBIX_HOST} {CHASSIS_DISCOVERY_KEY} {disc_json}\n")
    send_to_zabbix(disc_file)

def send_chassis_items(item_lines):
    """Chassis item değerlerini Zabbix'e gönderir"""
    chassis_file = os.path.join(TMP_DIR, "chassis_items.txt")
    with open(chassis_file, "w") as f:
        for line in item_lines:
            f.write(line.strip() + "\n")
    send_to_zabbix(chassis_file)

def build_blade_zabbix_data(blade_list, cache):
    """Blade verilerini Zabbix formatına dönüştürür"""
    current_blades = set()
    discovery_data = []
    item_lines = []

    for blade in blade_list:
        blade_dn = blade.attrib.get("dn", "")
        server_id = blade.attrib.get("serverId", "")
        model = blade.attrib.get("model", "")
        serial = blade.attrib.get("serial", "")
        chassis_id = blade.attrib.get("chassisId", "")
        slot_id = blade.attrib.get("slotId", "")
        
        # Power ve durum bilgileri
        oper_power = blade.attrib.get("operPower", "unknown")
        oper_state = blade.attrib.get("operState", "unknown")
        operability = blade.attrib.get("operability", "unknown")
        presence = blade.attrib.get("presence", "unknown")

        if not server_id:
            continue

        current_blades.add(server_id)

        # Discovery data'sına ekleme
        discovery_data.append({
            "{#BLADE_ID}": server_id,
            "{#BLADE_DN}": blade_dn,
            "{#BLADE_MODEL}": model,
            "{#BLADE_SERIAL}": serial,
            "{#CHASSIS_ID}": chassis_id,
            "{#SLOT_ID}": slot_id,
            "{#BLADE_NAME}": f"{blade_dn} ({model})"
        })

        # Item değerlerini hazırlama
        # Power state mapping (on=1, off=0, unknown=2)
        power_value = 1 if oper_power == "on" else (0 if oper_power == "off" else 2)
        
        # Oper state mapping (associated=1, unassociated=0, unknown=2)
        oper_value = 1 if oper_state == "associated" else (0 if oper_state == "unassociated" else 2)
        
        # Operability mapping (operable=0, inoperable=1, degraded=2, unknown=3)
        operability_mapping = {"operable": 0, "inoperable": 1, "degraded": 2}
        operability_value = operability_mapping.get(operability, 3)
        
        # Presence mapping (equipped=1, missing=0, unknown=2)
        presence_value = 1 if presence == "equipped" else (0 if presence == "missing" else 2)

        # Debug log
        log(f"Blade {server_id}: power='{oper_power}'→{power_value}, oper='{oper_state}'→{oper_value}, operability='{operability}'→{operability_value}, presence='{presence}'→{presence_value}")
        
        # Item'ları ekleme
        item_lines.append(f"{ZABBIX_HOST} {BLADE_KEYS['power_state']}[{server_id}] {power_value}")
        item_lines.append(f"{ZABBIX_HOST} {BLADE_KEYS['oper_state']}[{server_id}] {oper_value}")
        item_lines.append(f"{ZABBIX_HOST} {BLADE_KEYS['operability']}[{server_id}] {operability_value}")
        item_lines.append(f"{ZABBIX_HOST} {BLADE_KEYS['presence']}[{server_id}] {presence_value}")

        # Cache'e ekleme
        cache[server_id] = {
            "model": model,
            "serial": serial,
            "chassis_id": chassis_id,
            "slot_id": slot_id,
            "last_seen": datetime.now().isoformat()
        }

    # Artık mevcut olmayan blade'leri cache'den temizleme
    for server_id in list(cache):
        if server_id not in current_blades:
            del cache[server_id]

    return discovery_data, item_lines, cache

def send_blade_discovery(discovery_data):
    """Blade discovery verilerini Zabbix'e gönderir"""
    disc_file = os.path.join(TMP_DIR, "blade_discovery.txt")
    disc_json = json.dumps({"data": discovery_data}, ensure_ascii=False)
    with open(disc_file, "w", encoding="utf-8") as f:
        f.write(f"{ZABBIX_HOST} {BLADE_DISCOVERY_KEY} {disc_json}\n")
    send_to_zabbix(disc_file)

def send_blade_items(item_lines):
    """Blade item değerlerini Zabbix'e gönderir"""
    blade_file = os.path.join(TMP_DIR, "blade_items.txt")
    with open(blade_file, "w") as f:
        for line in item_lines:
            f.write(line.strip() + "\n")
    send_to_zabbix(blade_file)

def build_fi_zabbix_data(fi_list, cache):
    """Fabric Interconnect verilerini Zabbix formatına dönüştürür"""
    current_fis = set()
    discovery_data = []
    item_lines = []

    for fi in fi_list:
        fi_id = fi.attrib.get("id", "")
        fi_dn = fi.attrib.get("dn", "")
        model = fi.attrib.get("model", "")
        serial = fi.attrib.get("serial", "")
        oob_ip = fi.attrib.get("oobIfIp", "")
        
        # Durum bilgileri
        operability = fi.attrib.get("operability", "unknown")
        thermal = fi.attrib.get("thermal", "unknown")
        total_memory = fi.attrib.get("totalMemory", "0")
        diff_memory = fi.attrib.get("diffMemory", "0")
        flt_aggr = fi.attrib.get("fltAggr", "0")

        if not fi_id:
            continue

        current_fis.add(fi_id)

        # Discovery data'sına ekleme
        discovery_data.append({
            "{#FI_ID}": fi_id,
            "{#FI_DN}": fi_dn,
            "{#FI_MODEL}": model,
            "{#FI_SERIAL}": serial,
            "{#FI_IP}": oob_ip,
            "{#FI_NAME}": f"{fi_dn} ({model})"
        })

        # Item değerlerini hazırlama
        # Operability mapping (operable=0, inoperable=1, degraded=2, unknown=3)
        operability_mapping = {"operable": 0, "inoperable": 1, "degraded": 2}
        operability_value = operability_mapping.get(operability, 3)
        
        # Thermal mapping (ok=0, problem=1, unknown=2)
        thermal_value = 0 if thermal == "ok" else (1 if thermal in ["upper-critical", "lower-critical", "upper-non-critical", "lower-non-critical"] else 2)
        
        # Memory usage percentage calculation - (totalMemory - expectedMemory) / totalMemory * 100
        try:
            total_mem = int(total_memory)
            expected_mem = int(fi.attrib.get("expectedMemory", "0"))
            used_mem = total_mem - expected_mem
            memory_usage_pct = round((used_mem / total_mem) * 100, 2) if total_mem > 0 else 0
            # Negatif değerleri 0 yap
            memory_usage_pct = max(0, memory_usage_pct)
        except (ValueError, ZeroDivisionError):
            memory_usage_pct = 0
        
        # Fault count - büyük bit flag değerlerini bit sayısına çevir
        try:
            fault_aggr_raw = int(flt_aggr)
            # Eğer değer çok büyükse (bit flag), aktif bit sayısını hesapla
            if fault_aggr_raw > 1000000:  # 1 milyon üzerindeyse bit flag olabilir
                fault_count = bin(fault_aggr_raw).count('1')  # Aktif bit sayısı
            else:
                fault_count = fault_aggr_raw
        except ValueError:
            fault_count = 0

        # Debug log
        log(f"FI {fi_id}: operability='{operability}'→{operability_value}, thermal='{thermal}'→{thermal_value}, memory={memory_usage_pct}%, faults={fault_count}")
        
        # Item'ları ekleme
        item_lines.append(f"{ZABBIX_HOST} {FI_KEYS['operability']}[{fi_id}] {operability_value}")
        item_lines.append(f"{ZABBIX_HOST} {FI_KEYS['thermal']}[{fi_id}] {thermal_value}")
        item_lines.append(f"{ZABBIX_HOST} {FI_KEYS['memory_usage']}[{fi_id}] {memory_usage_pct}")
        item_lines.append(f"{ZABBIX_HOST} {FI_KEYS['fault_count']}[{fi_id}] {fault_count}")

        # Cache'e ekleme
        cache[fi_id] = {
            "model": model,
            "serial": serial,
            "ip": oob_ip,
            "last_seen": datetime.now().isoformat()
        }

    # Artık mevcut olmayan FI'ları cache'den temizleme
    for fi_id in list(cache):
        if fi_id not in current_fis:
            del cache[fi_id]

    return discovery_data, item_lines, cache

def send_fi_discovery(discovery_data):
    """Fabric Interconnect discovery verilerini Zabbix'e gönderir"""
    disc_file = os.path.join(TMP_DIR, "fi_discovery.txt")
    disc_json = json.dumps({"data": discovery_data}, ensure_ascii=False)
    with open(disc_file, "w", encoding="utf-8") as f:
        f.write(f"{ZABBIX_HOST} {FI_DISCOVERY_KEY} {disc_json}\n")
    send_to_zabbix(disc_file)

def send_fi_items(item_lines):
    """Fabric Interconnect item değerlerini Zabbix'e gönderir"""
    fi_file = os.path.join(TMP_DIR, "fi_items.txt")
    with open(fi_file, "w") as f:
        for line in item_lines:
            f.write(line.strip() + "\n")
    send_to_zabbix(fi_file)

def build_port_zabbix_data(port_list, cache):
    """Fabric Interconnect portlarını Zabbix formatına dönüştürür (sadece enabled portlar)"""
    current_ports = set()
    discovery_data = []
    item_lines = []

    for port in port_list:
        port_id = port.attrib.get("portId", "")
        port_dn = port.attrib.get("dn", "")
        switch_id = port.attrib.get("switchId", "")
        slot_id = port.attrib.get("slotId", "")
        chassis_id = port.attrib.get("chassisId", "")
        
        # Port durumları
        admin_state = port.attrib.get("adminState", "unknown")
        oper_state = port.attrib.get("operState", "unknown")
        if_role = port.attrib.get("ifRole", "unknown")
        oper_speed = port.attrib.get("operSpeed", "unknown")
        peer_dn = port.attrib.get("peerDn", "")

        # Sadece enabled portları izle
        if admin_state != "enabled":
            continue

        if not port_id or not switch_id:
            continue

        port_key = f"{switch_id}-{slot_id}-{port_id}"
        current_ports.add(port_key)

        # Discovery data'sına ekleme
        discovery_data.append({
            "{#PORT_KEY}": port_key,
            "{#PORT_ID}": port_id,
            "{#PORT_DN}": port_dn,
            "{#SWITCH_ID}": switch_id,
            "{#SLOT_ID}": slot_id,
            "{#CHASSIS_ID}": chassis_id,
            "{#PEER_DN}": peer_dn,
            "{#PORT_NAME}": f"Port {port_id} (Switch {switch_id})"
        })

        # Item değerlerini hazırlama
        # Admin state mapping (enabled=1, disabled=0, unknown=2)
        admin_value = 1 if admin_state == "enabled" else (0 if admin_state == "disabled" else 2)
        
        # Oper state mapping (up=1, down=0, indeterminate=2, link-down=3, unknown=4)
        oper_mapping = {"up": 1, "down": 0, "indeterminate": 2, "link-down": 3}
        oper_value = oper_mapping.get(oper_state, 4)
        
        # If role mapping (server=1, unknown=0, uplink=2)
        role_mapping = {"server": 1, "unknown": 0, "uplink": 2}
        role_value = role_mapping.get(if_role, 0)

        # Debug log
        log(f"Port {port_key}: admin='{admin_state}'→{admin_value}, oper='{oper_state}'→{oper_value}, role='{if_role}'→{role_value}")
        
        # Item'ları ekleme
        item_lines.append(f"{ZABBIX_HOST} {PORT_KEYS['admin_state']}[{port_key}] {admin_value}")
        item_lines.append(f"{ZABBIX_HOST} {PORT_KEYS['oper_state']}[{port_key}] {oper_value}")
        item_lines.append(f"{ZABBIX_HOST} {PORT_KEYS['if_role']}[{port_key}] {role_value}")

        # Cache'e ekleme
        cache[port_key] = {
            "switch_id": switch_id,
            "slot_id": slot_id,
            "port_id": port_id,
            "chassis_id": chassis_id,
            "last_seen": datetime.now().isoformat()
        }

    # Artık mevcut olmayan portları cache'den temizleme
    for port_key in list(cache):
        if port_key not in current_ports:
            del cache[port_key]

    return discovery_data, item_lines, cache

def send_port_discovery(discovery_data):
    """Port discovery verilerini Zabbix'e gönderir"""
    disc_file = os.path.join(TMP_DIR, "port_discovery.txt")
    disc_json = json.dumps({"data": discovery_data}, ensure_ascii=False)
    with open(disc_file, "w", encoding="utf-8") as f:
        f.write(f"{ZABBIX_HOST} {PORT_DISCOVERY_KEY} {disc_json}\n")
    send_to_zabbix(disc_file)

def send_port_items(item_lines):
    """Port item değerlerini Zabbix'e gönderir"""
    port_file = os.path.join(TMP_DIR, "port_items.txt")
    with open(port_file, "w") as f:
        for line in item_lines:
            f.write(line.strip() + "\n")
    send_to_zabbix(port_file)

def build_server_if_zabbix_data(server_if_list, cache):
    """Server Interface portlarını Zabbix formatına dönüştürür"""
    current_interfaces = set()
    discovery_data = []
    item_lines = []

    for server_if in server_if_list:
        port_id = server_if.attrib.get("portId", "")
        if_dn = server_if.attrib.get("dn", "")
        switch_id = server_if.attrib.get("switchId", "")
        slot_id = server_if.attrib.get("slotId", "")
        chassis_id = server_if.attrib.get("chassisId", "")
        
        # Interface durumları
        admin_state = server_if.attrib.get("adminState", "unknown")
        oper_state = server_if.attrib.get("operState", "unknown")
        if_role = server_if.attrib.get("ifRole", "unknown")
        peer_dn = server_if.attrib.get("peerDn", "")
        locale = server_if.attrib.get("locale", "")

        if not port_id or not switch_id:
            continue

        if_key = f"{switch_id}-{chassis_id}-{slot_id}-{port_id}"
        current_interfaces.add(if_key)

        # Discovery data'sına ekleme
        discovery_data.append({
            "{#IF_KEY}": if_key,
            "{#PORT_ID}": port_id,
            "{#IF_DN}": if_dn,
            "{#SWITCH_ID}": switch_id,
            "{#SLOT_ID}": slot_id,
            "{#CHASSIS_ID}": chassis_id,
            "{#PEER_DN}": peer_dn,
            "{#LOCALE}": locale,
            "{#IF_NAME}": f"Server Interface {port_id} (Chassis {chassis_id}, Switch {switch_id})"
        })

        # Item değerlerini hazırlama
        # Admin state mapping (enabled=1, disabled=0, unknown=2)
        admin_value = 1 if admin_state == "enabled" else (0 if admin_state == "disabled" else 2)
        
        # Oper state mapping (up=1, down=0, indeterminate=2, link-down=3, unknown=4)
        oper_mapping = {"up": 1, "down": 0, "indeterminate": 2, "link-down": 3}
        oper_value = oper_mapping.get(oper_state, 4)

        # Debug log - özellikle link-down durumlarını göster
        if oper_state == "link-down":
            log(f"⚠️  Server Interface {if_key}: LINK-DOWN detected! peer='{peer_dn}'")
        else:
            log(f"Server Interface {if_key}: admin='{admin_state}'→{admin_value}, oper='{oper_state}'→{oper_value}")
        
        # Item'ları ekleme
        item_lines.append(f"{ZABBIX_HOST} {SERVER_IF_KEYS['admin_state']}[{if_key}] {admin_value}")
        item_lines.append(f"{ZABBIX_HOST} {SERVER_IF_KEYS['oper_state']}[{if_key}] {oper_value}")

        # Cache'e ekleme
        cache[if_key] = {
            "switch_id": switch_id,
            "chassis_id": chassis_id,
            "slot_id": slot_id,
            "port_id": port_id,
            "peer_dn": peer_dn,
            "last_seen": datetime.now().isoformat()
        }

    # Artık mevcut olmayan interface'leri cache'den temizleme
    for if_key in list(cache):
        if if_key not in current_interfaces:
            del cache[if_key]

    return discovery_data, item_lines, cache

def send_server_if_discovery(discovery_data):
    """Server Interface discovery verilerini Zabbix'e gönderir"""
    disc_file = os.path.join(TMP_DIR, "server_if_discovery.txt")
    disc_json = json.dumps({"data": discovery_data}, ensure_ascii=False)
    with open(disc_file, "w", encoding="utf-8") as f:
        f.write(f"{ZABBIX_HOST} {SERVER_IF_DISCOVERY_KEY} {disc_json}\n")
    send_to_zabbix(disc_file)

def send_server_if_items(item_lines):
    """Server Interface item değerlerini Zabbix'e gönderir"""
    server_if_file = os.path.join(TMP_DIR, "server_if_items.txt")
    with open(server_if_file, "w") as f:
        for line in item_lines:
            f.write(line.strip() + "\n")
    send_to_zabbix(server_if_file)

def main():
    log("UCS fault verileri alınıyor...")
    cookie = login_ucs()
    faults = get_faults(cookie)
    log(f"Toplam {len(faults)} faultInst bulundu.")

    cache = load_cache()
    discovery_data, item_lines, updated_cache = build_zabbix_data(faults, cache)

    log("1. Discovery verileri gönderiliyor...")
    send_discovery_only(discovery_data)

    log("2. Zabbix item'larının oluşması için bekleniyor...")
    time.sleep(5)

    log("3. Alarm değerleri gönderiliyor...")
    send_items_only(item_lines)

    save_cache(updated_cache)
    
    # Chassis monitoring eklentisi
    log("UCS chassis verileri alınıyor...")
    chassis_list = get_chassis(cookie)
    log(f"Toplam {len(chassis_list)} chassis bulundu.")

    chassis_cache = load_chassis_cache()
    chassis_discovery, chassis_items, updated_chassis_cache = build_chassis_zabbix_data(chassis_list, chassis_cache)

    log("4. Chassis discovery verileri gönderiliyor...")
    send_chassis_discovery(chassis_discovery)

    log("5. Chassis item'larının oluşması için bekleniyor...")
    time.sleep(3)

    log("6. Chassis değerleri gönderiliyor...")
    send_chassis_items(chassis_items)

    save_chassis_cache(updated_chassis_cache)
    
    # Blade monitoring eklentisi
    log("UCS blade verileri alınıyor...")
    blade_list = get_blades(cookie)
    log(f"Toplam {len(blade_list)} blade bulundu.")

    blade_cache = load_blade_cache()
    blade_discovery, blade_items, updated_blade_cache = build_blade_zabbix_data(blade_list, blade_cache)

    log("7. Blade discovery verileri gönderiliyor...")
    send_blade_discovery(blade_discovery)

    log("8. Blade item'larının oluşması için bekleniyor...")
    time.sleep(3)

    log("9. Blade değerleri gönderiliyor...")
    send_blade_items(blade_items)

    save_blade_cache(updated_blade_cache)
    
    # Fabric Interconnect monitoring eklentisi
    log("UCS fabric interconnect verileri alınıyor...")
    fi_list = get_fabric_interconnects(cookie)
    log(f"Toplam {len(fi_list)} fabric interconnect bulundu.")

    fi_cache = load_fi_cache()
    fi_discovery, fi_items, updated_fi_cache = build_fi_zabbix_data(fi_list, fi_cache)

    log("10. Fabric Interconnect discovery verileri gönderiliyor...")
    send_fi_discovery(fi_discovery)

    log("11. Fabric Interconnect item'larının oluşması için bekleniyor...")
    time.sleep(3)

    log("12. Fabric Interconnect değerleri gönderiliyor...")
    send_fi_items(fi_items)

    save_fi_cache(updated_fi_cache)
    
    # Port monitoring eklentisi
    log("UCS port verileri alınıyor...")
    port_list = get_ports(cookie)
    log(f"Toplam {len(port_list)} port bulundu.")

    port_cache = load_port_cache()
    port_discovery, port_items, updated_port_cache = build_port_zabbix_data(port_list, port_cache)

    log("13. Port discovery verileri gönderiliyor...")
    send_port_discovery(port_discovery)

    log("14. Port item'larının oluşması için bekleniyor...")
    time.sleep(3)

    log("15. Port değerleri gönderiliyor...")
    send_port_items(port_items)

    save_port_cache(updated_port_cache)
    
    # Server Interface monitoring eklentisi
    log("UCS server interface verileri alınıyor...")
    server_if_list = get_server_interfaces(cookie)
    log(f"Toplam {len(server_if_list)} server interface bulundu.")

    server_if_cache = load_server_if_cache()
    server_if_discovery, server_if_items, updated_server_if_cache = build_server_if_zabbix_data(server_if_list, server_if_cache)

    log("16. Server Interface discovery verileri gönderiliyor...")
    send_server_if_discovery(server_if_discovery)

    log("17. Server Interface item'larının oluşması için bekleniyor...")
    time.sleep(3)

    log("18. Server Interface değerleri gönderiliyor...")
    send_server_if_items(server_if_items)

    save_server_if_cache(updated_server_if_cache)
    
    log("Zabbix gönderimi tamamlandı.")

if __name__ == "__main__":
    main()
