import ipaddress
import socket
import subprocess
import platform
import re
import threading
from concurrent.futures import ThreadPoolExecutor
import time
import os
import sys

# ==========================================
# DETEKSI OS
# ==========================================
IS_WINDOWS = platform.system() == 'Windows'
IS_LINUX = platform.system() == 'Linux'
IS_MAC = platform.system() == 'Darwin'

# ==========================================
# FUNGSI BANTUAN
# ==========================================
def get_local_ip():
    """Dapatkan IP lokal perangkat."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return '127.0.0.1'

def get_network_range(ip, mask=24):
    """Dapatkan range jaringan dari IP dan mask."""
    try:
        network = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
        return network
    except Exception:
        return ipaddress.IPv4Network('192.168.1.0/24')

def ping_host(ip, timeout=1):
    """
    Ping satu IP untuk cek apakah host aktif.
    
    Args:
        ip (str): IP address
        timeout (int): Timeout dalam detik
    
    Returns:
        bool: True jika host aktif
    """
    try:
        if IS_WINDOWS:
            cmd = ['ping', '-n', '1', '-w', str(int(timeout * 1000)), ip]
        else:
            cmd = ['ping', '-c', '1', '-W', str(timeout), ip]
        
        result = subprocess.run(cmd, capture_output=True, timeout=timeout+1)
        return result.returncode == 0
    except Exception:
        return False

def get_hostname(ip):
    """Dapatkan hostname dari IP."""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except Exception:
        return None

def arp_scan(ip_range):
    """
    Scan ARP untuk menemukan host aktif (Linux/Mac).
    """
    hosts = []
    try:
        if IS_LINUX:
            cmd = ['arp-scan', '--localnet']
        elif IS_MAC:
            cmd = ['arp', '-a']
        else:
            return []
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        output = result.stdout
        
        # Parse ARP output
        for line in output.split('\n'):
            ip_match = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', line)
            mac_match = re.search(r'([0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2})', line)
            
            if ip_match and mac_match:
                ip = ip_match.group(1)
                mac = mac_match.group(1)
                if ipaddress.ip_address(ip) in ipaddress.ip_network(ip_range, strict=False):
                    hostname = get_hostname(ip)
                    hosts.append({
                        'ip': ip,
                        'mac': mac,
                        'hostname': hostname or 'Unknown'
                    })
    except Exception:
        pass
    
    return hosts

# ==========================================
# FUNGSI UTAMA (DISCOVERY)
# ==========================================
def discover_hosts(ip_range=None, mask=24, max_threads=50):
    """
    Temukan perangkat aktif di jaringan.
    
    Args:
        ip_range (str): Range IP (contoh: 192.168.1.0/24)
        mask (int): Netmask (default: 24)
        max_threads (int): Jumlah thread maksimal
    
    Returns:
        dict: {
            'network': str,
            'total_hosts': int,
            'active_hosts': int,
            'hosts': list,
            'scan_time': float
        }
    """
    start_time = time.time()
    
    # Validasi mask
    try:
        mask = int(mask)
        if mask < 8 or mask > 30:
            mask = 24
    except (ValueError, TypeError):
        mask = 24

    # Dapatkan IP lokal jika range tidak diberikan
    if not ip_range or not str(ip_range).strip():
        local_ip = get_local_ip()
        network = get_network_range(local_ip, mask)
        ip_range = str(network)
    else:
        ip_range = str(ip_range).strip()
    
    # Pastikan format CIDR benar
    if '/' not in ip_range:
        if ip_range.count('.') == 3:
            ip_range = f"{ip_range}/{mask}"
        else:
            ip_range = f"192.168.1.0/{mask}"
    
    try:
        network = ipaddress.IPv4Network(ip_range, strict=False)
    except Exception:
        return {'error': f'Invalid network range: {ip_range}'}
    
    # Generate semua IP dalam range
    all_ips = [str(ip) for ip in network.hosts()]
    total_hosts = len(all_ips)
    
    # Coba ARP scan dulu (jika didukung OS)
    arp_hosts = arp_scan(ip_range)
    arp_ips = set([h['ip'] for h in arp_hosts])
    
    active_hosts = list(arp_hosts)
    active_ips = set(arp_ips)
    
    # Lock untuk thread-safe operation saat memodifikasi list/set bersama
    lock = threading.Lock()
    
    def ping_and_add(ip):
        with lock:
            if ip in active_ips:
                return
                
        if ping_host(ip):
            hostname = get_hostname(ip)
            with lock:
                if ip not in active_ips:
                    active_hosts.append({
                        'ip': ip,
                        'mac': 'Unknown (Ping)',
                        'hostname': hostname or 'Unknown'
                    })
                    active_ips.add(ip)
    
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        executor.map(ping_and_add, all_ips)
    
    scan_time = time.time() - start_time
    
    # Urutkan berdasarkan alamat IP
    try:
        active_hosts.sort(key=lambda x: ipaddress.ip_address(x['ip']))
    except Exception:
        pass
    
    return {
        'network': str(network),
        'total_hosts': total_hosts,
        'active_hosts': len(active_hosts),
        'hosts': active_hosts,
        'scan_time': round(scan_time, 2)
    }

# ==========================================
# TESTING UNIT
# ==========================================
if __name__ == '__main__':
    print("=" * 50)
    print("HOST DISCOVERY - TESTING")
    print("=" * 50)
    
    local_ip = get_local_ip()
    print(f"[*] Local IP: {local_ip}")
    
    print("[*] Scanning local network...")
    results = discover_hosts()
    
    if 'error' in results:
        print(f"[!] Error: {results['error']}")
    else:
        print(f"\n[*] Network: {results['network']}")
        print(f"[*] Total Hosts: {results['total_hosts']}")
        print(f"[*] Active Hosts: {results['active_hosts']}")
        print(f"[*] Scan Time: {results['scan_time']}s")
        
        if results['hosts']:
            print("\n[*] Active Hosts:")
            for idx, host in enumerate(results['hosts'], 1):
                print(f"    {idx}. {host['ip']} - {host['hostname']} ({host['mac']})")
        else:
            print("\n[!] No active hosts found.")
    
    print("\n[*] Selesai.")