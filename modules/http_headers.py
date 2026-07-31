import requests
import ssl
import socket
from urllib.parse import urlparse

# ==========================================
# DAFTAR SECURITY HEADERS PENTING
# ==========================================
SECURITY_HEADERS = {
    'Content-Security-Policy': 'CSP - Mencegah XSS dan injeksi konten',
    'X-Frame-Options': 'Mencegah clickjacking',
    'X-Content-Type-Options': 'Mencegah MIME sniffing',
    'Strict-Transport-Security': 'HSTS - Memaksa HTTPS',
    'Referrer-Policy': 'Mengontrol informasi referer',
    'X-XSS-Protection': 'XSS protection (legacy)',
    'Permissions-Policy': 'Mengontrol fitur browser',
    'Cross-Origin-Embedder-Policy': 'COEP - Keamanan cross-origin',
    'Cross-Origin-Opener-Policy': 'COOP - Keamanan cross-origin',
    'Cross-Origin-Resource-Policy': 'CORP - Keamanan cross-origin'
}

# ==========================================
# FUNGSI ANALISIS HEADER
# ==========================================
def get_headers(url):
    """
    Dapatkan HTTP headers dari URL.
    
    Args:
        url (str): URL target
    
    Returns:
        dict: Detail HTTP headers dan analisis keamanan
    """
    if not url or not str(url).strip():
        return {'error': 'URL tidak boleh kosong'}
    
    url = str(url).strip()
    
    # Normalisasi URL jika belum memiliki skema (http:// atau https://)
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    headers_req = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    }

    try:
        r = requests.get(url, headers=headers_req, timeout=10, allow_redirects=True)
        
        result = {
            'url': url,
            'status_code': r.status_code,
            'headers': dict(r.headers),
            'cookies': r.cookies.get_dict(),
            'redirects': [resp.url for resp in r.history],
            'final_url': r.url
        }
        
        # Security analysis
        security_analysis = {}
        for header, desc in SECURITY_HEADERS.items():
            if header in r.headers:
                val = r.headers[header]
                status_str = '✅ Good'
                
                # Catatan khusus untuk HSTS max-age=0
                if header == 'Strict-Transport-Security' and 'max-age=0' in val:
                    status_str = '⚠️ Warning (max-age=0)'
                    
                security_analysis[header] = {
                    'present': True,
                    'value': val,
                    'description': desc,
                    'status': status_str
                }
            else:
                security_analysis[header] = {
                    'present': False,
                    'value': None,
                    'description': desc,
                    'status': '❌ Missing'
                }
        
        # Server info
        result['server_info'] = r.headers.get('Server', 'Unknown')
        
        # X-Powered-By (informasi tambahan)
        result['powered_by'] = r.headers.get('X-Powered-By', 'Unknown')
        
        result['security_analysis'] = security_analysis
        
        # Score keamanan
        present_count = sum(1 for h in security_analysis.values() if h['present'])
        total_count = len(security_analysis)
        result['security_score'] = {
            'present': present_count,
            'total': total_count,
            'percentage': round((present_count / total_count) * 100, 2)
        }
        
        return result
        
    except requests.exceptions.SSLError:
        return {'error': 'SSL Error - Sertifikat SSL tidak valid atau kadaluarsa'}
    except requests.exceptions.ConnectionError:
        return {'error': 'Connection Error - Host tidak dapat dijangkau'}
    except requests.exceptions.Timeout:
        return {'error': 'Timeout - Server tidak merespon dalam waktu 10 detik'}
    except requests.exceptions.InvalidURL:
        return {'error': 'Format URL tidak valid'}
    except Exception as e:
        return {'error': str(e)}

# ==========================================
# TESTING UNIT
# ==========================================
if __name__ == '__main__':
    print("=" * 50)
    print("HTTP HEADER ANALYZER - TESTING")
    print("=" * 50)
    
    test_url = "google.com"  # Menguji URL tanpa https://
    print(f"[*] Analyzing: {test_url}")
    
    result = get_headers(test_url)
    
    if 'error' in result:
        print(f"[!] Error: {result['error']}")
    else:
        print(f"\n[*] Status Code: {result['status_code']}")
        print(f"[*] Server: {result['server_info']}")
        print(f"[*] Security Score: {result['security_score']['present']}/{result['security_score']['total']} ({result['security_score']['percentage']}%)")
        
        print("\n[*] Security Headers:")
        for header, info in result['security_analysis'].items():
            status = info['status']
            value = info['value'] if info['present'] else '❌'
            print(f"    {status} {header}: {value}")
    
    print("\n[*] Selesai.")