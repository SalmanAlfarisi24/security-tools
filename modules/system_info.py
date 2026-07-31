import os
import platform
import subprocess
import psutil
import datetime
import sys

# ==========================================
# DETEKSI OS
# ==========================================
IS_WINDOWS = platform.system() == 'Windows'
IS_LINUX = platform.system() == 'Linux'
IS_MAC = platform.system() == 'Darwin'

# ==========================================
# FUNGSI GET SYSTEM INFO
# ==========================================
def get_system_info():
    """
    Dapatkan informasi sistem lengkap secara real-time.
    
    Returns:
        dict: Informasi rinci tentang OS, CPU, Memori, Disk, Network, dan Uptime.
    """
    info = {
        'os': {},
        'cpu': {},
        'memory': {},
        'disk': {},
        'network': {},
        'uptime': {},
        'timestamp': datetime.datetime.now().isoformat()
    }
    
    # ===== OS INFORMATION =====
    try:
        info['os'] = {
            'system': platform.system(),
            'release': platform.release(),
            'version': platform.version(),
            'machine': platform.machine(),
            'processor': platform.processor(),
            'hostname': platform.node(),
            'platform': platform.platform()
        }
    except Exception as e:
        info['os'] = {'error': f'Gagal mendapatkan OS info: {str(e)}'}
    
    # ===== CPU INFORMATION =====
    try:
        cpu_freq = psutil.cpu_freq()
        info['cpu'] = {
            'physical_cores': psutil.cpu_count(logical=False) or 0,
            'logical_cores': psutil.cpu_count(logical=True) or 0,
            'max_frequency': f"{cpu_freq.max:.2f} MHz" if cpu_freq and cpu_freq.max else 'N/A',
            'min_frequency': f"{cpu_freq.min:.2f} MHz" if cpu_freq and cpu_freq.min else 'N/A',
            'current_frequency': f"{cpu_freq.current:.2f} MHz" if cpu_freq and cpu_freq.current else 'N/A',
            # Interval dikurangi dari 1s ke 0.1s untuk menghindari latency request pada Flask
            'usage_percent': psutil.cpu_percent(interval=0.1),
            'usage_per_core': psutil.cpu_percent(interval=0.1, percpu=True)
        }
    except Exception as e:
        info['cpu'] = {'error': f'Gagal mendapatkan CPU info: {str(e)}'}
    
    # ===== MEMORY INFORMATION =====
    try:
        mem = psutil.virtual_memory()
        swap = psutil.swap_memory()
        info['memory'] = {
            'total': {
                'bytes': mem.total,
                'human': format_bytes(mem.total)
            },
            'available': {
                'bytes': mem.available,
                'human': format_bytes(mem.available)
            },
            'used': {
                'bytes': mem.used,
                'human': format_bytes(mem.used)
            },
            'percentage': mem.percent,
            'swap_total': {
                'bytes': swap.total,
                'human': format_bytes(swap.total)
            } if swap else None,
            'swap_used': {
                'bytes': swap.used,
                'human': format_bytes(swap.used)
            } if swap else None,
            'swap_percentage': swap.percent if swap else 0
        }
    except Exception as e:
        info['memory'] = {'error': f'Gagal mendapatkan Memory info: {str(e)}'}
    
    # ===== DISK INFORMATION =====
    try:
        disk_info = []
        partitions = psutil.disk_partitions(all=False)
        for partition in partitions:
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                disk_info.append({
                    'device': partition.device,
                    'mountpoint': partition.mountpoint,
                    'fstype': partition.fstype,
                    'total': {
                        'bytes': usage.total,
                        'human': format_bytes(usage.total)
                    },
                    'used': {
                        'bytes': usage.used,
                        'human': format_bytes(usage.used)
                    },
                    'free': {
                        'bytes': usage.free,
                        'human': format_bytes(usage.free)
                    },
                    'percentage': usage.percent
                })
            except (PermissionError, OSError):
                continue
        info['disk'] = disk_info
    except Exception as e:
        info['disk'] = {'error': f'Gagal mendapatkan Disk info: {str(e)}'}
    
    # ===== NETWORK INFORMATION =====
    try:
        net_info = []
        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
        
        for interface, addr_list in addrs.items():
            if interface in stats and stats[interface].isup:
                net = {
                    'interface': interface,
                    'addresses': []
                }
                for addr in addr_list:
                    net['addresses'].append({
                        'family': addr.family.name if hasattr(addr.family, 'name') else str(addr.family),
                        'address': addr.address,
                        'netmask': addr.netmask,
                        'broadcast': getattr(addr, 'broadcast', None)
                    })
                
                net['mtu'] = stats[interface].mtu
                net['speed'] = stats[interface].speed
                net['duplex'] = stats[interface].duplex
                
                net_info.append(net)
        
        info['network'] = net_info
    except Exception as e:
        info['network'] = {'error': f'Gagal mendapatkan Network info: {str(e)}'}
    
    # ===== UPTIME =====
    try:
        boot_time = psutil.boot_time()
        uptime_seconds = datetime.datetime.now().timestamp() - boot_time
        info['uptime'] = {
            'boot_time': datetime.datetime.fromtimestamp(boot_time).strftime('%Y-%m-%d %H:%M:%S'),
            'uptime_seconds': round(uptime_seconds, 2),
            'uptime_human': format_uptime(uptime_seconds)
        }
    except Exception as e:
        info['uptime'] = {'error': f'Gagal mendapatkan Uptime info: {str(e)}'}
    
    return info

# ==========================================
# FUNGSI HELPER
# ==========================================
def format_bytes(bytes_value):
    """Format bytes ke satuan yang mudah dibaca (Human Readable)."""
    if not bytes_value or bytes_value < 0:
        return "0 B"
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_value < 1024.0:
            return f"{bytes_value:.2f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.2f} PB"

def format_uptime(seconds):
    """Format nilai detik uptime ke format Hari, Jam, Menit, Detik."""
    if not seconds or seconds < 0:
        return "0s"
    days = int(seconds // 86400)
    hours = int((seconds % 86400) // 3600)
    minutes = int((seconds % 3600) // 60)
    secs = int(seconds % 60)
    
    parts = []
    if days > 0:
        parts.append(f"{days}d")
    if hours > 0:
        parts.append(f"{hours}h")
    if minutes > 0:
        parts.append(f"{minutes}m")
    if secs > 0 or not parts:
        parts.append(f"{secs}s")
    
    return " ".join(parts)

# ==========================================
# TESTING UNIT
# ==========================================
if __name__ == '__main__':
    print("=" * 50)
    print("SYSTEM INFORMATION - TESTING")
    print("=" * 50)
    
    info = get_system_info()
    
    if isinstance(info.get('os'), dict) and 'system' in info['os']:
        print(f"\n[*] OS: {info['os']['system']} {info['os']['release']}")
        print(f"[*] Hostname: {info['os']['hostname']}")
    
    if isinstance(info.get('cpu'), dict) and 'usage_percent' in info['cpu']:
        print(f"[*] CPU: {info['cpu']['physical_cores']} Cores ({info['cpu']['logical_cores']} Threads), Usage: {info['cpu']['usage_percent']}%")
    
    if isinstance(info.get('memory'), dict) and 'percentage' in info['memory']:
        print(f"[*] RAM: {info['memory']['used']['human']} / {info['memory']['total']['human']} ({info['memory']['percentage']}%)")
    
    if isinstance(info.get('disk'), list) and info['disk']:
        for disk in info['disk'][:2]:
            print(f"[*] Disk {disk['device']} ({disk['mountpoint']}): {disk['used']['human']} / {disk['total']['human']} ({disk['percentage']}%)")
    
    if isinstance(info.get('uptime'), dict) and 'uptime_human' in info['uptime']:
        print(f"[*] Uptime: {info['uptime']['uptime_human']}")
    
    print("\n[*] Selesai.")