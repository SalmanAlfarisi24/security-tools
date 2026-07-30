import requests
from concurrent.futures import ThreadPoolExecutor
import time

# ==========================================
# WORDLIST DEFAULT
# ==========================================
DEFAULT_WORDLIST = [
    'admin', 'login', 'dashboard', 'panel', 'wp-admin',
    'phpmyadmin', 'pma', 'adminer', 'backup', 'backups',
    'tmp', 'temp', 'logs', 'log', 'debug', 'test',
    'dev', 'api', 'v1', 'v2', 'v3', 'static',
    'assets', 'images', 'css', 'js', 'fonts',
    'upload', 'uploads', 'files', 'download', 'downloads',
    'data', 'config', 'conf', 'includes', 'inc',
    'lib', 'libs', 'src', 'modules', 'mods',
    'user', 'users', 'account', 'profile', 'settings',
    'help', 'support', 'contact', 'about', 'home',
    'news', 'blog', 'post', 'page', 'posts',
    '2023', '2024', '2025', 'archive', 'old'
]

# =========================================
# FUNGSI BANTUAN
# =========================================
def check_directory(url, path, timeout=3):
    """
    Cek apakah direktori/file ada di server.
    
    Args:
        url (str): Base URL (contoh: http://example.com)
        path (str): Path yang akan dicek (contoh: admin)
        timeout (int): Timeout request
    
    Returns:
        dict atau None: {
            'path': str,
            'url': str,
            'status_code': int,
            'content_length': int,
            'title': str (opsional)
        }
    """
    target_url = f"{url.rstrip('/')}/{path}"
    try:
        r = requests.get(target_url, timeout=timeout, allow_redirects=True)
        
        # Cek apakah ditemukan (status 2xx atau 3xx)
        if 200 <= r.status_code < 400:
            # Ambil title jika ada
            title = ''
            if '<title>' in r.text:
                start = r.text.find('<title>') + 7
                end = r.text.find('</title>', start)
                if end > start:
                    title = r.text[start:end].strip()
            
            return {
                'path': path,
                'url': target_url,
                'status_code': r.status_code,
                'content_length': len(r.content),
                'title': title[:50] if title else '-'
            }
        return None
    except requests.exceptions.Timeout:
        return {'error': 'timeout', 'path': path}
    except requests.exceptions.ConnectionError:
        return {'error': 'connection', 'path': path}
    except Exception:
        return None

# ==========================================
# FUNGSI UTAMA
# ==========================================
def brute_directories(url, wordlist=None, max_threads=30, timeout=3):
    """
    Brute force direktori pada target URL.
    
    Args:
        url (str): Base URL target
        wordlist (list): Daftar path yang akan dicoba
        max_threads (int): Jumlah thread maksimal
        timeout (int): Timeout request
    
    Returns:
        tuple: (list hasil, jumlah ditemukan, total dicoba)
    """
    if wordlist is None:
        wordlist = DEFAULT_WORDLIST
    
    results = []
    total = len(wordlist)
    
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = [executor.submit(check_directory, url, path, timeout) for path in wordlist]
        
        for future in futures:
            result = future.result()
            if result:
                # Skip error/timeout
                if isinstance(result, dict) and 'error' in result:
                    continue
                results.append(result)
    
    found = len(results)
    return results, found, total

# ==========================================
# FUNGSI UNTUK TESTING (JALAN LANGUSNG)
# ==========================================
if __name__ == '__main__':
    print("=" * 50)
    print("DIRECTORY BRUTE - TESTING")
    print("=" * 50)
    
    test_url = "http://testphp.vulnweb.com"
    print(f"[*] Target: {test_url}")
    print("[*] Menggunakan wordlist default...")
    print("[*] Mohon tunggu...")
    
    start = time.time()
    results, found, total = brute_directories(test_url)
    elapsed = time.time() - start
    
    print(f"\n[*] Hasil:")
    print(f"    Total dicoba: {total}")
    print(f"    Ditemukan: {found}")
    print(f"    Waktu: {elapsed:.2f}s")
    
    if results:
        # Kelompokkan berdasarkan status code
        print("\n[*] Daftar direktori ditemukan:")
        for idx, item in enumerate(results, 1):
            status = item['status_code']
            status_icon = '✅' if status == 200 else '🟡' if 300 <= status < 400 else '🔴'
            print(f"    {idx}. {status_icon} {item['path']} -> {status} | {item['content_length']} bytes | {item['title'][:30]}")
    else:
        print("\n[!] Tidak ada direktori ditemukan.")
    
    print("\n[*] Selesai.")