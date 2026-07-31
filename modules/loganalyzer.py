import re
import ipaddress
from collections import Counter
from datetime import datetime

# ==========================================
# POLA DETEKSI
# ==========================================
PATTERNS = {
    'ip': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
    'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
    'url': r'https?://[^\s]+',
    'timestamp': r'\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}',
    'status_code': r'\b[1-5][0-9]{2}\b',
    'method': r'\b(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\b',
    'user_agent': r'[A-Za-z]+/[0-9.]+(?:\s*\([^)]*\))?(?:\s*[A-Za-z]+/[0-9.]+)*',
    'error': r'\b(error|fail|invalid|denied|timeout|exception)\b',
    'admin_access': r'/admin|/dashboard|/panel|/cpanel|/wp-admin|/phpmyadmin',
    'suspicious': r'\.\./|union select|drop table|<script|eval\(|base64_decode'
}

# ==========================================
# FUNGSI ANALISIS
# ==========================================
def extract_patterns(text, pattern_name):
    """Ekstrak semua pola dari teks."""
    pattern = PATTERNS.get(pattern_name)
    if not pattern:
        return []
    return re.findall(pattern, text, re.IGNORECASE)

def analyze_log(log_content):
    """
    Analisis log content dan deteksi pola serangan.
    
    Args:
        log_content (str): Isi log yang akan dianalisis
    
    Returns:
        dict: Hasil analisis lengkap
    """
    lines = log_content.split('\n')
    total_lines = len(lines)
    
    results = {
        'total_lines': total_lines,
        'empty_lines': 0,
        'ips': [],
        'emails': [],
        'urls': [],
        'status_codes': [],
        'methods': [],
        'timestamps': [],
        'errors': [],
        'admin_access': [],
        'suspicious': [],
        'user_agents': [],
        'ip_stats': {},
        'status_stats': {},
        'method_stats': {},
        'error_stats': {},
        'suspicious_logs': []
    }
    
    for line in lines:
        if not line.strip():
            results['empty_lines'] += 1
            continue
        
        # Ekstrak berbagai pola
        ips = extract_patterns(line, 'ip')
        results['ips'].extend(ips)
        
        emails = extract_patterns(line, 'email')
        results['emails'].extend(emails)
        
        urls = extract_patterns(line, 'url')
        results['urls'].extend(urls)
        
        status_codes = extract_patterns(line, 'status_code')
        results['status_codes'].extend(status_codes)
        
        methods = extract_patterns(line, 'method')
        results['methods'].extend(methods)
        
        timestamps = extract_patterns(line, 'timestamp')
        results['timestamps'].extend(timestamps)
        
        # Deteksi error
        if re.search(PATTERNS['error'], line, re.IGNORECASE):
            results['errors'].append(line[:200])
        
        # Deteksi akses admin
        if re.search(PATTERNS['admin_access'], line, re.IGNORECASE):
            results['admin_access'].append(line[:200])
        
        # Deteksi suspicious
        if re.search(PATTERNS['suspicious'], line, re.IGNORECASE):
            results['suspicious'].append(line[:200])
            results['suspicious_logs'].append({
                'line': line[:200],
                'type': 'suspicious_pattern'
            })
    
    # Statistik IP
    if results['ips']:
        ip_counter = Counter(results['ips'])
        results['ip_stats'] = dict(ip_counter.most_common(10))
    
    # Statistik status code
    if results['status_codes']:
        status_counter = Counter(results['status_codes'])
        results['status_stats'] = dict(status_counter.most_common(10))
    
    # Statistik method
    if results['methods']:
        method_counter = Counter(results['methods'])
        results['method_stats'] = dict(method_counter)
    
    # Statistik error
    if results['errors']:
        error_counter = Counter(results['errors'])
        results['error_stats'] = dict(error_counter.most_common(5))
    
    # Hapus duplikat untuk list
    results['ips'] = list(set(results['ips']))[:20]
    results['emails'] = list(set(results['emails']))[:20]
    results['urls'] = list(set(results['urls']))[:20]
    results['status_codes'] = list(set(results['status_codes']))[:20]
    results['methods'] = list(set(results['methods']))[:20]
    results['timestamps'] = list(set(results['timestamps']))[:20]
    results['user_agents'] = list(set(results['user_agents']))[:20]
    
    # Deteksi serangan berdasarkan pola
    attack_detected = []
    
    if results['suspicious_logs']:
        attack_detected.append('SQL Injection / XSS attempt detected')
    
    if results['admin_access']:
        attack_detected.append('Admin panel access detected')
    
    if results['status_stats'].get('404', 0) > 10:
        attack_detected.append('Possible directory brute force (many 404)')
    
    if results['status_stats'].get('500', 0) > 5:
        attack_detected.append('Server errors detected')
    
    if len(results['ips']) > 50:
        attack_detected.append('High number of unique IPs')
    
    results['attack_detected'] = attack_detected
    
    return results

# ==========================================
# FUNGSI UNTUK TESTING (JALAN LANGUSNG)
# ==========================================
if __name__ == '__main__':
    print("=" * 50)
    print("LOG ANALYZER - TESTING")
    print("=" * 50)
    
    # Sample log
    sample_log = """
    2024-01-15 10:00:01 GET /index.php 200 192.168.1.1 Mozilla/5.0
    2024-01-15 10:00:02 POST /login.php 302 192.168.1.2 Mozilla/5.0
    2024-01-15 10:00:03 GET /admin/dashboard 403 10.0.0.1 curl/7.68.0
    2024-01-15 10:00:04 GET /index.php?page=../../../etc/passwd 404 192.168.1.3 python-requests
    2024-01-15 10:00:05 POST /login.php 200 192.168.1.2 Mozilla/5.0
    2024-01-15 10:00:06 GET /phpmyadmin 404 10.0.0.2 Mozilla/5.0
    2024-01-15 10:00:07 GET /index.php?q=1' OR '1'='1 500 192.168.1.4 sqlmap/1.0
    2024-01-15 10:00:08 POST /api/v1/upload 200 192.168.1.1 Mozilla/5.0
    2024-01-15 10:00:09 GET /admin/config.php 403 10.0.0.3 curl/7.68.0
    2024-01-15 10:00:10 GET /index.php?x=<script>alert(1)</script> 400 192.168.1.5 Mozilla/5.0
    """
    
    print("[*] Analyzing sample log...")
    results = analyze_log(sample_log)
    
    print(f"\n[*] Total lines: {results['total_lines']}")
    print(f"[*] Empty lines: {results['empty_lines']}")
    
    print("\n[*] IPs found:")
    for ip in results['ips'][:10]:
        print(f"    - {ip}")
    
    print("\n[*] Status codes:")
    for code, count in results['status_stats'].items():
        print(f"    - {code}: {count}x")
    
    print("\n[*] Attack detected:")
    if results['attack_detected']:
        for attack in results['attack_detected']:
            print(f"    ⚠️ {attack}")
    else:
        print("    ✅ No attacks detected")
    
    if results['suspicious_logs']:
        print("\n[*] Suspicious lines:")
        for item in results['suspicious_logs'][:3]:
            print(f"    - {item['line']}")
    
    print("\n[*] Selesai.")