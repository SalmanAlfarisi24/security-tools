import subprocess
import re
import time
import os
import platform
from concurrent.futures import ThreadPoolExecutor

# =========================================
# DETEKSI OS
# =========================================
IS_WINDOWS = platform.system() == 'Windows'
IS_LINUX = platform.system() == 'Linux'
IS_MAC = platform.system() == 'Darwin'

# ==========================================
# FUNGSI BANTUAN
# ==========================================
def get_windows_wifi():
    """
    Scan WiFi di Windows menggunakan netsh.
    """
    try:
        # Jalankan netsh untuk scan
        subprocess.run(['netsh', 'wlan', 'show', 'networks'], 
                      capture_output=True, timeout=5)
        # Ambil hasil
        result = subprocess.run(['netsh', 'wlan', 'show', 'networks', 'mode=bssid'],
                              capture_output=True, text=True, timeout=10)
        output = result.stdout
        
        networks = []
        current_ssid = None
        current_bssid = None
        current_channel = None
        current_signal = None
        current_auth = None
        
        lines = output.split('\n')
        for line in lines:
            line = line.strip()
            
            # Cari SSID
            if line.startswith('SSID'):
                ssid_match = re.search(r'SSID\s+:\s(.+)', line)
                if ssid_match:
                    current_ssid = ssid_match.group(1)
            
            # Cari BSSID
            if 'BSSID' in line:
                bssid_match = re.search(r'BSSID\s+:\s([0-9a-fA-F:]+)', line)
                if bssid_match:
                    current_bssid = bssid_match.group(1)
            
            # Cari Channel
            if 'Channel' in line:
                channel_match = re.search(r'Channel\s+:\s(\d+)', line)
                if channel_match:
                    current_channel = int(channel_match.group(1))
            
            # Cari Signal
            if 'Signal' in line:
                signal_match = re.search(r'Signal\s+:\s(\d+)%', line)
                if signal_match:
                    current_signal = int(signal_match.group(1))
            
            # Cari Authentication
            if 'Authentication' in line:
                auth_match = re.search(r'Authentication\s+:\s(.+)', line)
                if auth_match:
                    current_auth = auth_match.group(1)
            
            # Simpan network jika ada BSSID
            if current_bssid and current_ssid and 'BSSID' in line:
                networks.append({
                    'ssid': current_ssid,
                    'bssid': current_bssid,
                    'channel': current_channel or 0,
                    'signal': current_signal or 0,
                    'auth': current_auth or 'Unknown',
                    'encryption': 'Unknown'
                })
                # Reset untuk network berikutnya
                current_bssid = None
        
        # Jika tidak ada hasil, coba mode dasar
        if not networks:
            result = subprocess.run(['netsh', 'wlan', 'show', 'networks'],
                                  capture_output=True, text=True, timeout=10)
            lines = result.stdout.split('\n')
            for line in lines:
                if 'SSID' in line and ':' in line:
                    ssid_match = re.search(r'SSID\s+:\s(.+)', line)
                    if ssid_match:
                        networks.append({
                            'ssid': ssid_match.group(1),
                            'bssid': 'Unknown',
                            'channel': 0,
                            'signal': 0,
                            'auth': 'Unknown',
                            'encryption': 'Unknown'
                        })
        
        return networks
    except Exception as e:
        return {'error': f'Windows scan error: {str(e)}'}

def get_linux_wifi(interface='wlan0', duration=10):
    """
    Scan WiFi di Linux menggunakan iwlist atau airodump-ng.
    """
    networks = []
    
    # Coba pakai iwlist
    try:
        # Scan dengan iwlist
        subprocess.run(['sudo', 'iwlist', interface, 'scan'], 
                      capture_output=True, timeout=duration+5)
        
        # Ambil hasil
        result = subprocess.run(['sudo', 'iwlist', interface, 'scan'],
                              capture_output=True, text=True, timeout=duration+5)
        output = result.stdout
        
        # Parse hasil iwlist
        cells = re.split(r'Cell \d+ - Address:', output)
        for cell in cells[1:]:
            ssid_match = re.search(r'ESSID:"([^"]+)"', cell)
            bssid_match = re.search(r'Address: ([0-9a-fA-F:]+)', cell)
            channel_match = re.search(r'Channel:(\d+)', cell)
            signal_match = re.search(r'Quality=(\d+)/\d+', cell)
            encryption_match = re.search(r'Encryption key:(\w+)', cell)
            
            ssid = ssid_match.group(1) if ssid_match else 'Hidden'
            bssid = bssid_match.group(1) if bssid_match else 'Unknown'
            channel = int(channel_match.group(1)) if channel_match else 0
            signal = int(signal_match.group(1)) if signal_match else 0
            encryption = 'WPA2' if encryption_match and encryption_match.group(1) == 'on' else 'Open'
            
            networks.append({
                'ssid': ssid,
                'bssid': bssid,
                'channel': channel,
                'signal': signal,
                'auth': 'WPA2' if encryption == 'WPA2' else 'Open',
                'encryption': encryption
            })
        
        return networks
    except:
        pass
    
    # Coba pakai airodump-ng jika iwlist gagal
    try:
        temp_file = '/tmp/wifi_scan'
        # Mulai airodump
        proc = subprocess.Popen(['sudo', 'airodump-ng', interface, '--write', temp_file],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(duration)
        proc.terminate()
        
        # Baca hasil
        with open(f'{temp_file}-01.csv', 'r') as f:
            lines = f.readlines()
        
        for line in lines:
            if 'Station' in line:
                continue
            parts = line.split(',')
            if len(parts) >= 6:
                bssid = parts[0].strip()
                channel = int(parts[3].strip()) if parts[3].strip().isdigit() else 0
                signal = int(parts[4].strip()) if parts[4].strip().isdigit() else 0
                encryption = parts[5].strip()
                auth = parts[6].strip() if len(parts) > 6 else 'Unknown'
                
                networks.append({
                    'ssid': parts[13].strip() if len(parts) > 13 and parts[13].strip() else 'Hidden',
                    'bssid': bssid,
                    'channel': channel,
                    'signal': signal,
                    'auth': auth,
                    'encryption': encryption
                })
        
        os.remove(f'{temp_file}-01.csv')
        return networks
    except:
        return {'error': 'Linux scan error: pastikan iwlist atau airodump-ng terinstall'}

def get_mac_wifi():
    """
    Scan WiFi di macOS menggunakan airport.
    """
    try:
        # Cari path airport
        airport_path = '/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport'
        if not os.path.exists(airport_path):
            return {'error': 'Airport not found'}
        
        result = subprocess.run([airport_path, '-s'], capture_output=True, text=True, timeout=10)
        output = result.stdout
        
        networks = []
        lines = output.split('\n')[1:]  # Skip header
        for line in lines:
            if line.strip():
                parts = line.split()
                if len(parts) >= 7:
                    ssid = ' '.join(parts[:-6])
                    bssid = parts[-6]
                    channel = int(parts[-5]) if parts[-5].isdigit() else 0
                    signal = int(parts[-4]) if parts[-4].isdigit() else 0
                    encryption = parts[-1]
                    
                    networks.append({
                        'ssid': ssid,
                        'bssid': bssid,
                        'channel': channel,
                        'signal': signal,
                        'auth': 'WPA2' if 'WPA' in encryption else 'Open',
                        'encryption': encryption
                    })
        
        return networks
    except Exception as e:
        return {'error': f'Mac scan error: {str(e)}'}

# ==========================================
# FUNGSI UTAMA
# ==========================================
def scan_wifi(interface='wlan0', duration=10):
    """
    Scan WiFi di sekitar.
    
    Args:
        interface (str): Interface WiFi (Linux/Mac)
        duration (int): Durasi scan (detik)
    
    Returns:
        list: Daftar jaringan WiFi ditemukan
    """
    if IS_WINDOWS:
        result = get_windows_wifi()
    elif IS_LINUX:
        result = get_linux_wifi(interface, duration)
    elif IS_MAC:
        result = get_mac_wifi()
    else:
        return {'error': 'OS tidak didukung'}
    
    # Sort by signal strength
    if isinstance(result, list) and result:
        result.sort(key=lambda x: x.get('signal', 0), reverse=True)
    
    return result

# ==========================================
# FUNGSI UNTUK TESTING (JALAN LANGUSNG)
# ==========================================
if __name__ == '__main__':
    print("=" * 50)
    print("WIFI SCANNER - TESTING")
    print("=" * 50)
    
    print(f"[*] OS: {platform.system()}")
    print("[*] Scanning WiFi...")
    
    results = scan_wifi(duration=5)
    
    if isinstance(results, dict) and 'error' in results:
        print(f"\n[!] Error: {results['error']}")
    elif not results:
        print("\n[!] Tidak ada jaringan ditemukan.")
    else:
        print(f"\n[*] Ditemukan {len(results)} jaringan:")
        for idx, net in enumerate(results, 1):
            signal_bar = '█' * (net['signal'] // 10) if net['signal'] > 0 else '?'
            print(f"    {idx}. {net['ssid']} ({signal_bar})")
            print(f"       BSSID: {net['bssid']} | Channel: {net['channel']} | Signal: {net['signal']}% | Auth: {net['auth']}")
    
    print("\n[*] Selesai.")