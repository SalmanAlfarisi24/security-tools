import ssl
import socket
import datetime
from datetime import timezone
import hashlib
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# ==========================================
# FUNGSI HELPER SANITISASI
# ==========================================
def sanitize_hostname(hostname):
    """Sanitasi hostname dan ekstrak port jika dicantumkan."""
    if not hostname or not str(hostname).strip():
        return None, 443
    
    hostname = str(hostname).strip().lower()
    if '://' in hostname:
        hostname = hostname.split('://')[1]
    hostname = hostname.split('/')[0]
    
    port = 443
    if ':' in hostname:
        parts = hostname.split(':')
        hostname = parts[0]
        try:
            port = int(parts[1])
        except ValueError:
            port = 443
            
    return hostname, port

# ==========================================
# FUNGSI SSL CHECKER
# ==========================================
def get_ssl_info(hostname, port=443):
    """
    Dapatkan informasi sertifikat SSL dari hostname.
    
    Args:
        hostname (str): Hostname target
        port (int): Port (default: 443)
    
    Returns:
        dict: Informasi sertifikat SSL
    """
    hostname, parsed_port = sanitize_hostname(hostname)
    if not hostname:
        return {'error': 'Hostname/Domain tidak boleh kosong', 'is_valid': False}
    
    if parsed_port != 443 and port == 443:
        port = parsed_port

    try:
        context = ssl.create_default_context()
        
        # Buka 1 koneksi socket saja untuk mengambil detail cipher, versi, dan DER cert
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert_dict = ssock.getpeercert()
                der_cert = ssock.getpeercert(binary_form=True)
                cipher = ssock.cipher()
                version = ssock.version()
        
        # Load cert object dari bytes DER langsung (tanpa koneksi ulang)
        cert_obj = x509.load_der_x509_certificate(der_cert, default_backend())
        
        # Compute Fingerprint
        fingerprint_sha256 = hashlib.sha256(der_cert).hexdigest()
        fingerprint_sha1 = hashlib.sha1(der_cert).hexdigest()
        
        # Extract Subject dan Issuer
        subject = {attr.oid._name: attr.value for attr in cert_obj.subject}
        issuer = {attr.oid._name: attr.value for attr in cert_obj.issuer}
        
        # Normalisasi Tanggal Validitas (Timezone Aware / Naive Safe)
        not_before = getattr(cert_obj, 'not_valid_before_utc', cert_obj.not_valid_before)
        not_after = getattr(cert_obj, 'not_valid_after_utc', cert_obj.not_valid_after)
        
        now = datetime.datetime.now(timezone.utc) if not_after.tzinfo else datetime.datetime.now()
        days_left = (not_after - now).days
        
        # Ekstrak Subject Alternative Names (SAN)
        san = []
        try:
            ext = cert_obj.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            san = [name.value for name in ext.value if isinstance(name, x509.DNSName)]
        except Exception:
            pass
        
        result = {
            'hostname': hostname,
            'port': port,
            'version': version,
            'cipher': {
                'name': cipher[0] if cipher else 'Unknown',
                'protocol': cipher[1] if cipher else 'Unknown',
                'bits': cipher[2] if cipher else 0
            },
            'subject': subject,
            'issuer': issuer,
            'not_before': not_before.strftime('%Y-%m-%d %H:%M:%S'),
            'not_after': not_after.strftime('%Y-%m-%d %H:%M:%S'),
            'days_left': days_left,
            'is_expired': days_left < 0,
            'fingerprint_sha256': fingerprint_sha256,
            'fingerprint_sha1': fingerprint_sha1,
            'serial_number': str(cert_obj.serial_number),
            'subject_alt_name': san,
            'is_valid': days_left >= 0
        }
        
        if cert_dict and 'ocsp' in cert_dict:
            result['ocsp'] = cert_dict['ocsp']
        if cert_dict and 'crlDistributionPoints' in cert_dict:
            result['crl'] = cert_dict['crlDistributionPoints']
        
        return result
        
    except ssl.SSLError as e:
        err_str = str(e).lower()
        if 'certificate has expired' in err_str:
            return {'error': 'Sertifikat SSL telah kadaluarsa', 'is_valid': False}
        elif 'self-signed' in err_str or 'self signed' in err_str:
            return {'error': 'Sertifikat SSL Self-Signed (Tidak Terpercaya)', 'is_valid': False}
        elif 'certificate verify failed' in err_str:
            return {'error': f'Verifikasi Sertifikat Gagal: {str(e)}', 'is_valid': False}
        else:
            return {'error': f'SSL Error: {str(e)}', 'is_valid': False}
    except socket.gaierror:
        return {'error': f'Hostname/Domain {hostname} tidak ditemukan', 'is_valid': False}
    except socket.timeout:
        return {'error': 'Koneksi timeout (server tidak merespon pada port SSL)', 'is_valid': False}
    except Exception as e:
        return {'error': str(e), 'is_valid': False}

# ==========================================
# TESTING UNIT
# ==========================================
if __name__ == '__main__':
    print("=" * 50)
    print("SSL/TLS CHECKER - TESTING")
    print("=" * 50)
    
    test_host = "https://google.com/search"  # Uji sanitasi
    print(f"[*] Checking SSL for: {test_host}")
    
    result = get_ssl_info(test_host)
    
    if 'error' in result and not result.get('is_valid'):
        print(f"[!] Error: {result['error']}")
    else:
        print(f"\n[*] Target Sanitized: {result['hostname']}:{result['port']}")
        print(f"[*] SSL Version: {result['version']}")
        print(f"[*] Cipher: {result['cipher']['name']} ({result['cipher']['bits']} bits)")
        print(f"[*] Subject: {result['subject'].get('commonName', 'N/A')}")
        print(f"[*] Issuer: {result['issuer'].get('commonName', 'N/A')}")
        print(f"[*] Valid From: {result['not_before']}")
        print(f"[*] Valid Until: {result['not_after']}")
        print(f"[*] Days Left: {result['days_left']}")
        print(f"[*] Status: {'✅ Valid' if not result['is_expired'] else '❌ Expired'}")
        if result.get('subject_alt_name'):
            print(f"[*] Subject Alt Names: {', '.join(result['subject_alt_name'][:3])}")
    
    print("\n[*] Selesai.")