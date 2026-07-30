import dns.resolver
import socket
import requests
from concurrent.futures import ThreadPoolExecutor

# =========================================
# WORDLIST DEFAULT
# =========================================
DEFAULT_WORDLIST = [
    'www', 'mail', 'ftp', 'admin', 'dev', 'test', 'api',
    'blog', 'shop', 'forum', 'support', 'portal', 'app',
    'ns1', 'ns2', 'dns', 'smtp', 'pop3', 'mysql', 'mssql',
    'webmail', 'cpanel', 'whm', 'ssh', 'vpn', 'remote',
    'backup', 'stage', 'demo', 'secure', 'partner', 'client',
    'mobile', 'wap', 'api2', 'v2', 'old', 'new', 'staging',
    'prod', 'production', 'uat', 'dev2', 'test2', 'admin2'
]

# ==========================================
# FUNGSI BANTUAN
# ==========================================
def check_dns(sub, domain):
    """
    Cek apakah subdomain terdaftar di DNS
    Menggunakan DNS resolver dan fallback HTTP request
    """
    target = f"{sub}.{domain}"
    
    # Coba DNS lookup
    try:
        dns.resolver.resolve(target, 'A')
        ip = socket.gethostbyname(target)
        return {
            'subdomain': target,
            'ip': ip,
            'status': 'active'
        }
    except:
        pass
    
    # Fallback: coba HTTP request
    try:
        for protocol in ['https', 'http']:
            url = f"{protocol}://{target}"
            r = requests.get(url, timeout=2)
            if r.status_code < 400:
                return {
                    'subdomain': target,
                    'ip': 'unknown (HTTP OK)',
                    'status': 'active'
                }
    except:
        pass
    
    return None

# ==========================================
# FUNGSI UTAMA
# ==========================================
def scan_subdomains(domain, wordlist=None):
    """
    Scan subdomain dari domain target.
    
    Args:
        domain (str): Domain target (contoh: example.com)
        wordlist (list): Daftar subdomain yang akan dicoba (opsional)
    
    Returns:
        tuple: (list hasil, total dicoba, jumlah ditemukan)
    """
    if wordlist is None:
        wordlist = DEFAULT_WORDLIST
    
    results = []
    total = len(wordlist)
    
    with ThreadPoolExecutor(max_workers=30) as executor:
        # Kirim semua task ke thread pool
        futures = [executor.submit(check_dns, sub, domain) for sub in wordlist]
        
        # Kumpulkan hasil
        for future in futures:
            result = future.result()
            if result:
                results.append(result)
    
    found = len(results)
    return results, total, found

# ==========================================
# FUNGSI UNTUK TESTING (JALAN LANGUSNG)
# ==========================================
if __name__ == '__main__':
    # Contoh penggunaan jika file dijalankan langsung
    print("=" * 50)
    print("SUBDOMAIN FINDER - TESTING")
    print("=" * 50)
    
    test_domain = "example.com"
    print(f"[*] Scanning: {test_domain}")
    print("[*] Menggunakan wordlist default...")
    
    results, total, found = scan_subdomains(test_domain)
    
    print(f"\n[*] Hasil:")
    print(f"    Total dicoba: {total}")
    print(f"    Ditemukan: {found}")
    
    if results:
        print("\n[*] Daftar subdomain ditemukan:")
        for idx, item in enumerate(results, 1):
            print(f"    {idx}. {item['subdomain']} -> {item['ip']}")
    else:
        print("\n[!] Tidak ada subdomain ditemukan.")
    
    print("\n[*] Selesai.")