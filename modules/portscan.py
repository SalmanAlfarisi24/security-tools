import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor

# =========================================
# KONFIGURASI DEFAULT
# =========================================
COMMON_PORTS = {
    20: 'FTP-data',
    21: 'FTP',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    80: 'HTTP',
    110: 'POP3',
    111: 'RPCbind',
    135: 'MSRPC',
    139: 'NetBIOS-SSN',
    143: 'IMAP',
    443: 'HTTPS',
    445: 'SMB',
    993: 'IMAPS',
    995: 'POP3S',
    1433: 'MSSQL',
    1521: 'Oracle',
    1723: 'PPTP',
    3306: 'MySQL',
    3389: 'RDP',
    5432: 'PostgreSQL',
    5900: 'VNC',
    6379: 'Redis',
    8080: 'HTTP-Alt',
    8443: 'HTTPS-Alt',
    27017: 'MongoDB'
}

TIMEOUT = 1.0
MAX_THREADS = 50

# ==========================================
# FUNGSI CEK PORT
# ==========================================
def check_port(target, port, timeout=TIMEOUT):
    """
    Cek apakah port terbuka pada target.
    
    Args:
        target (str): IP atau domain target
        port (int): Nomor port yang akan dicek
        timeout (float): Waktu tunggu koneksi (detik)
    
    Returns:
        dict atau None: {'port': int, 'service': str, 'status': str}
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((target, port))
        sock.close()
        
        if result == 0:
            service = COMMON_PORTS.get(port, 'unknown')
            return {
                'port': port,
                'service': service,
                'status': 'open'
            }
        return None
    except socket.gaierror:
        # Domain tidak valid
        return {'error': 'Invalid target'}
    except Exception:
        return None

# ==========================================
# FUNGSI UTAMA
# ==========================================
def scan_ports(target, ports=None, timeout=TIMEOUT, max_threads=MAX_THREADS):
    """
    Scan port terbuka pada target.
    
    Args:
        target (str): IP atau domain target
        ports (list): Daftar port yang akan discan (default: COMMON_PORTS)
        timeout (float): Waktu tunggu koneksi (detik)
        max_threads (int): Jumlah thread maksimal
    
    Returns:
        dict: {
            'target': str,
            'results': list,
            'open_count': int,
            'closed_count': int,
            'error': str (optional)
        }
    """
    if ports is None:
        ports = list(COMMON_PORTS.keys())
    
    results = []
    open_count = 0
    closed_count = 0
    
    try:
        # Resolve target ke IP
        ip = socket.gethostbyname(target)
        target_display = ip
    except socket.gaierror:
        return {
            'target': target,
            'results': [],
            'open_count': 0,
            'closed_count': 0,
            'error': 'Target tidak valid atau tidak bisa diresolve'
        }
    
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        # Kirim semua task ke thread pool
        futures = [executor.submit(check_port, target, port, timeout) for port in ports]
        
        # Kumpulkan hasil
        for future in futures:
            result = future.result()
            if result:
                if 'error' in result:
                    return {
                        'target': target_display,
                        'results': [],
                        'open_count': 0,
                        'closed_count': 0,
                        'error': result['error']
                    }
                results.append(result)
                open_count += 1
            else:
                closed_count += 1
    
    # Urutkan hasil berdasarkan port
    results.sort(key=lambda x: x['port'])
    
    return {
        'target': target_display,
        'results': results,
        'open_count': open_count,
        'closed_count': closed_count,
        'error': None
    }

# ==========================================
# FUNGSI UNTUK TESTING (JALAN LANGUSNG)
# ==========================================
if __name__ == '__main__':
    print("=" * 50)
    print("PORT SCANNER - TESTING")
    print("=" * 50)
    
    test_target = "scanme.nmap.org"
    print(f"[*] Scanning: {test_target}")
    print("[*] Menggunakan daftar port default...")
    
    result = scan_ports(test_target)
    
    if result['error']:
        print(f"\n[!] Error: {result['error']}")
    else:
        print(f"\n[*] Hasil scan untuk: {result['target']}")
        print(f"    Port terbuka: {result['open_count']}")
        print(f"    Port tertutup: {result['closed_count']}")
        
        if result['results']:
            print("\n[*] Daftar port terbuka:")
            for item in result['results']:
                print(f"    {item['port']} ({item['service']}) -> OPEN")
        else:
            print("\n[!] Tidak ada port terbuka ditemukan.")
    
    print("\n[*] Selesai.")