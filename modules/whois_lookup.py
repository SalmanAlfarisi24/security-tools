import whois
from datetime import datetime

# ==========================================
# FUNGSI WHOIS LOOKUP
# ==========================================
def get_whois(domain):
    """
    Dapatkan informasi WHOIS dari domain.
    
    Args:
        domain (str): Domain target
    
    Returns:
        dict: Informasi WHOIS domain
    """
    if not domain:
        return {'error': 'Domain tidak boleh kosong'}

    # Sanitasi URL/Domain input (menghapus http://, path, atau port)
    domain = domain.strip().lower()
    if '://' in domain:
        domain = domain.split('://')[1]
    domain = domain.split('/')[0].split(':')[0]

    try:
        w = whois.whois(domain)
        
        result = {
            'domain': domain,
            'registrar': w.registrar,
            'whois_server': w.whois_server,
            'creation_date': w.creation_date,
            'expiration_date': w.expiration_date,
            'updated_date': w.updated_date,
            'name_servers': w.name_servers,
            'status': w.status,
            'emails': w.emails,
            'dnssec': w.dnssec,
            'org': w.org,
            'country': w.country,
            'state': w.state,
            'city': w.city,
            'address': w.address,
            'zipcode': w.zipcode,
            'phone': w.phone,
            'fax': w.fax,
            'is_expired': False,
            'days_left': 0
        }
        
        # Helper untuk mengambil objek datetime tunggal jika mengembalikan list
        def parse_date_obj(date_val):
            if not date_val:
                return None
            if isinstance(date_val, list):
                return date_val[0]
            return date_val

        # Hitung status expired & sisa hari sebelum format tanggal diubah ke string
        exp_date_obj = parse_date_obj(w.expiration_date)
        if exp_date_obj and isinstance(exp_date_obj, datetime):
            now = datetime.now()
            result['is_expired'] = exp_date_obj < now
            result['days_left'] = (exp_date_obj - now).days if not result['is_expired'] else 0
        
        # Format tanggal menjadi string konsisten untuk UI
        for field in ['creation_date', 'expiration_date', 'updated_date']:
            val = result[field]
            if val:
                if isinstance(val, list):
                    result[field] = [d.strftime('%Y-%m-%d %H:%M:%S') if isinstance(d, datetime) else str(d) for d in val]
                elif isinstance(val, datetime):
                    result[field] = val.strftime('%Y-%m-%d %H:%M:%S')
                else:
                    result[field] = str(val)

        return result
        
    except whois.parser.PywhoisError as e:
        return {'error': f'WHOIS error: {str(e)}'}
    except Exception as e:
        return {'error': str(e)}

# ==========================================
# TESTING UNIT
# ==========================================
if __name__ == '__main__':
    print("=" * 50)
    print("WHOIS LOOKUP - TESTING")
    print("=" * 50)
    
    test_domain = "google.com"
    print(f"[*] WHOIS untuk: {test_domain}")
    
    result = get_whois(test_domain)
    
    if 'error' in result:
        print(f"[!] Error: {result['error']}")
    else:
        print(f"\n[*] Registrar: {result.get('registrar', 'N/A')}")
        print(f"[*] Creation Date: {result.get('creation_date', 'N/A')}")
        print(f"[*] Expiration Date: {result.get('expiration_date', 'N/A')}")
        print(f"[*] Name Servers: {', '.join(result.get('name_servers', [])[:3]) if result.get('name_servers') else 'N/A'}")
        if result.get('is_expired') is not None:
            print(f"[*] Status: {'Expired' if result['is_expired'] else 'Active'}")
            if not result['is_expired']:
                print(f"[*] Days left: {result['days_left']}")
    
    print("\n[*] Selesai.")