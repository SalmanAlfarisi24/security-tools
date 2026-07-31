import subprocess
import platform
import re
import socket
import time

# ==========================================
# DETEKSI OS
# ==========================================
IS_WINDOWS = platform.system() == 'Windows'
IS_LINUX = platform.system() == 'Linux'
IS_MAC = platform.system() == 'Darwin'

# ==========================================
# FUNGSI HELPER SANITISASI
# ==========================================
def sanitize_target(target):
    """Sanitasi hostname/IP agar bersih dari protocol dan path."""
    if not target or not str(target).strip():
        return None
    target = str(target).strip().lower()
    if '://' in target:
        target = target.split('://')[1]
    target = target.split('/')[0].split(':')[0]
    return target

# ==========================================
# FUNGSI PING
# ==========================================
def ping_host(hostname, count=4):
    """
    Ping hostname untuk cek konektivitas.
    
    Args:
        hostname (str): Hostname target
        count (int): Jumlah paket ping
    
    Returns:
        dict: Detail hasil tes ping
    """
    hostname = sanitize_target(hostname)
    if not hostname:
        return {'error': 'Hostname/IP tidak boleh kosong'}

    try:
        count = max(1, min(int(count), 10))  # Batasi jumlah ping 1-10
    except (ValueError, TypeError):
        count = 4

    try:
        # Build ping command
        if IS_WINDOWS:
            cmd = ['ping', '-n', str(count), hostname]
        else:
            cmd = ['ping', '-c', str(count), hostname]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        output = result.stdout + result.stderr
        
        packets_sent = count
        packets_received = 0
        packets_lost = count
        min_time = None
        avg_time = None
        max_time = None
        
        if IS_WINDOWS:
            sent_match = re.search(r'Sent = (\d+)', output)
            received_match = re.search(r'Received = (\d+)', output)
            lost_match = re.search(r'Lost = (\d+)', output)
            time_match = re.search(r'Minimum = (\d+)ms, Maximum = (\d+)ms, Average = (\d+)ms', output)
            
            if sent_match:
                packets_sent = int(sent_match.group(1))
            if received_match:
                packets_received = int(received_match.group(1))
            if lost_match:
                packets_lost = int(lost_match.group(1))
            if time_match:
                min_time = float(time_match.group(1))
                max_time = float(time_match.group(2))
                avg_time = float(time_match.group(3))
        else:
            sent_match = re.search(r'(\d+) packets transmitted', output)
            received_match = re.search(r'(\d+) (?:packets )?received', output)
            time_match = re.search(r'min/avg/max(?:/mdev)? = ([\d.]+)/([\d.]+)/([\d.]+)', output)
            
            if sent_match:
                packets_sent = int(sent_match.group(1))
            if received_match:
                packets_received = int(received_match.group(1))
            if time_match:
                min_time = float(time_match.group(1))
                avg_time = float(time_match.group(2))
                max_time = float(time_match.group(3))

        packets_lost = max(0, packets_sent - packets_received)
        loss_percentage = (packets_lost / packets_sent * 100) if packets_sent > 0 else 100.0
        
        return {
            'host': hostname,
            'success': packets_received > 0,
            'packets_sent': packets_sent,
            'packets_received': packets_received,
            'packets_lost': packets_lost,
            'loss_percentage': round(loss_percentage, 2),
            'min_time': min_time,
            'avg_time': avg_time,
            'max_time': max_time,
            'output': output
        }
        
    except subprocess.TimeoutExpired:
        return {'error': 'Ping timeout (server tidak merespon)', 'host': hostname}
    except Exception as e:
        return {'error': str(e), 'host': hostname}

# ==========================================
# FUNGSI TRACEROUTE
# ==========================================
def traceroute_host(hostname, max_hops=30):
    """
    Traceroute ke hostname.
    
    Args:
        hostname (str): Hostname target
        max_hops (int): Jumlah maksimum hop
    
    Returns:
        dict: Daftar hop dan status traceroute
    """
    hostname = sanitize_target(hostname)
    if not hostname:
        return {'error': 'Hostname/IP tidak boleh kosong'}

    try:
        max_hops = max(1, min(int(max_hops), 30))
    except (ValueError, TypeError):
        max_hops = 30

    try:
        if IS_WINDOWS:
            cmd = ['tracert', '-h', str(max_hops), '-w', '1000', hostname]
        else:
            cmd = ['traceroute', '-m', str(max_hops), '-w', '1', hostname]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=45)
        output = result.stdout + result.stderr
        
        hops = []
        lines = output.split('\n')
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            if any(k in line.lower() for k in ['traceroute', 'tracing route', 'over a maximum']):
                continue
            
            parts = line.split()
            if not parts:
                continue
            
            try:
                if parts[0].isdigit():
                    hop_num = int(parts[0])
                    
                    # Ekstrak IP
                    ip = 'Request timed out'
                    ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
                    if ip_match:
                        ip = ip_match.group(0)
                    
                    # Ekstrak Waktu Response (ms)
                    times = [float(t) for t in re.findall(r'([\d.]+)\s*ms', line)]
                    
                    hops.append({
                        'hop': hop_num,
                        'ip': ip,
                        'times': times,
                        'avg_time': round(sum(times) / len(times), 2) if times else None
                    })
            except Exception:
                continue
        
        return {
            'host': hostname,
            'hops': hops,
            'success': len(hops) > 0,
            'output': output
        }
        
    except subprocess.TimeoutExpired:
        return {'error': 'Traceroute timeout (proses terlalu lama)', 'host': hostname}
    except Exception as e:
        return {'error': str(e), 'host': hostname}

# ==========================================
# TESTING UNIT
# ==========================================
if __name__ == '__main__':
    print("=" * 50)
    print("PING & TRACEROUTE - TESTING")
    print("=" * 50)
    
    test_host = "https://google.com/test"
    
    print(f"\n[*] PING: {test_host}")
    ping_result = ping_host(test_host)
    if 'error' in ping_result:
        print(f"[!] Error: {ping_result['error']}")
    else:
        print(f"    Target Sanitized: {ping_result['host']}")
        print(f"    Sent: {ping_result['packets_sent']}")
        print(f"    Received: {ping_result['packets_received']}")
        print(f"    Loss: {ping_result['loss_percentage']}%")
        if ping_result['avg_time']:
            print(f"    Avg Time: {ping_result['avg_time']}ms")
    
    print(f"\n[*] TRACEROUTE: {test_host}")
    trace_result = traceroute_host(test_host, max_hops=5)
    if 'error' in trace_result:
        print(f"[!] Error: {trace_result['error']}")
    else:
        print(f"    Hops Found: {len(trace_result['hops'])}")
        for hop in trace_result['hops'][:5]:
            print(f"      Hop {hop['hop']}: {hop['ip']} ({hop['avg_time']} ms)")
    
    print("\n[*] Selesai.")