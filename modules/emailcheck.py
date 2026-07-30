import re
import dns.resolver
import smtplib
import socket
from email_validator import validate_email as lib_validate

# ==========================================
# FUNGSI BANTUAN
# =========================================
def is_valid_format(email):
    """
    Cek format email menggunakan regex.
    """
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def get_mx_record(domain):
    """
    Dapatkan MX record untuk domain.
    """
    try:
        records = dns.resolver.resolve(domain, 'MX')
        mx_records = sorted([(r.preference, str(r.exchange).rstrip('.')) for r in records])
        return mx_records
    except dns.resolver.NoAnswer:
        return []
    except dns.resolver.NXDOMAIN:
        return []
    except Exception:
        return []

def check_smtp(email, mx_server, timeout=5):
    """
    Cek apakah email valid dengan SMTP.
    """
    try:
        # Ekstrak domain dari email
        domain = email.split('@')[1]
        
        # Coba konek ke SMTP server
        with smtplib.SMTP(mx_server, 25, timeout=timeout) as smtp:
            smtp.ehlo()
            smtp.mail('')
            code, message = smtp.rcpt(email)
            
            # 250 = OK, 550 = invalid, 5xx = error
            if code == 250:
                return True, 'Valid (SMTP OK)'
            elif code == 550:
                return False, 'Invalid (User not found)'
            elif code == 451:
                return True, 'Valid (Temporary error, but likely exists)'
            else:
                return None, f'Unknown response: {code} {message}'
    except smtplib.SMTPServerDisconnected:
        return None, 'SMTP server disconnected'
    except smtplib.SMTPConnectError:
        return None, 'Connection failed'
    except socket.timeout:
        return None, 'Timeout'
    except Exception as e:
        return None, str(e)

# ==========================================
# FUNGSI UTAMA
# ==========================================
def validate_email(email):
    """
    Validasi email secara lengkap.
    
    Args:
        email (str): Alamat email yang akan divalidasi
    
    Returns:
        dict: {
            'email': str,
            'format_valid': bool,
            'domain_valid': bool,
            'mx_records': list,
            'smtp_valid': bool or None,
            'smtp_message': str,
            'status': str,
            'suggestion': str (opsional)
        }
    """
    result = {
        'email': email,
        'format_valid': False,
        'domain_valid': False,
        'mx_records': [],
        'smtp_valid': None,
        'smtp_message': '',
        'status': 'invalid',
        'suggestion': ''
    }
    
    # Step 1: Cek format email
    if not is_valid_format(email):
        result['status'] = 'invalid_format'
        result['suggestion'] = 'Format email tidak valid. Contoh: user@domain.com'
        return result
    
    result['format_valid'] = True
    
    # Step 2: Ekstrak domain dan cek DNS
    domain = email.split('@')[1]
    try:
        # Cek apakah domain ada
        dns.resolver.resolve(domain, 'A')
        result['domain_valid'] = True
    except:
        result['domain_valid'] = False
        result['status'] = 'invalid_domain'
        result['suggestion'] = 'Domain tidak ditemukan atau tidak terdaftar'
        return result
    
    # Step 3: Dapatkan MX record
    mx_records = get_mx_record(domain)
    if not mx_records:
        result['status'] = 'no_mx'
        result['suggestion'] = 'Tidak ada MX record. Email mungkin tidak dapat menerima email.'
        result['mx_records'] = []
        return result
    
    result['mx_records'] = mx_records
    
    # Step 4: Coba SMTP check
    for priority, mx_server in mx_records[:3]:  # Coba 3 server teratas
        valid, message = check_smtp(email, mx_server)
        if valid is True:
            result['smtp_valid'] = True
            result['smtp_message'] = message
            result['status'] = 'valid'
            return result
        elif valid is False:
            result['smtp_valid'] = False
            result['smtp_message'] = message
            result['status'] = 'invalid_smtp'
            return result
        else:
            # None = error/timeout, lanjut ke server berikutnya
            continue
    
    # Jika semua server gagal atau timeout
    if result['smtp_valid'] is None:
        result['smtp_message'] = 'SMTP check failed (timeout or server error)'
        result['status'] = 'unknown'
        result['suggestion'] = 'Tidak dapat verifikasi via SMTP. Email mungkin valid atau server blocking.'
    
    return result

# ==========================================
# FUNGSI UNTUK TESTING (JALAN LANGUSNG)
# ==========================================
if __name__ == '__main__':
    print("=" * 50)
    print("EMAIL VALIDATOR - TESTING")
    print("=" * 50)
    
    test_emails = [
        'test@example.com',
        'user@gmail.com',
        'invalid@notexist.xyz',
        'admin@google.com',
        'fake@domain.tld'
    ]
    
    for email in test_emails:
        print(f"\n[*] Validasi: {email}")
        result = validate_email(email)
        print(f"    Format: {'✅' if result['format_valid'] else '❌'}")
        print(f"    Domain: {'✅' if result['domain_valid'] else '❌'}")
        print(f"    Status: {result['status']}")
        if result['mx_records']:
            print(f"    MX: {result['mx_records'][:3]}")
        if result['suggestion']:
            print(f"    Saran: {result['suggestion']}")
    
    print("\n[*] Selesai.")