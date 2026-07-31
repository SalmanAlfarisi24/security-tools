import dns.resolver
import dns.exception
import socket

# ==========================================
# FUNGSI DNS LOOKUP
# ==========================================
def get_dns_records(domain):
    """
    Dapatkan semua record DNS dari domain.
    
    Args:
        domain (str): Domain target
    
    Returns:
        dict: Hasil pencarian DNS per tipe record
    """
    if not domain or not str(domain).strip():
        return {'error': 'Domain tidak boleh kosong'}
    
    # Sanitasi domain input
    domain = str(domain).strip().lower()
    if '://' in domain:
        domain = domain.split('://')[1]
    domain = domain.split('/')[0].split(':')[0]
    
    results = {
        'A': [],
        'AAAA': [],
        'CNAME': [],
        'MX': [],
        'NS': [],
        'TXT': [],
        'SOA': [],
        'PTR': []
    }
    
    # Konfigurasi resolver dengan timeout ketat agar tidak mengunci Flask
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3.0
    resolver.lifetime = 5.0
    
    record_types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA']
    
    for record_type in record_types:
        try:
            answers = resolver.resolve(domain, record_type)
            for answer in answers:
                if record_type == 'MX':
                    results[record_type].append({
                        'preference': answer.preference,
                        'exchange': str(answer.exchange).rstrip('.')
                    })
                elif record_type == 'SOA':
                    results[record_type].append({
                        'mname': str(answer.mname).rstrip('.'),
                        'rname': str(answer.rname).rstrip('.'),
                        'serial': answer.serial,
                        'refresh': answer.refresh,
                        'retry': answer.retry,
                        'expire': answer.expire,
                        'minimum': answer.minimum
                    })
                else:
                    results[record_type].append(str(answer).rstrip('.'))
        except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            # Record tipe ini tidak ada pada domain, lanjut ke tipe berikutnya
            continue
        except dns.resolver.NXDOMAIN:
            return {'error': f'Domain {domain} tidak ditemukan (NXDOMAIN)'}
        except dns.exception.Timeout:
            # Jika satu query timeout, lanjutkan query record jenis lain
            continue
        except Exception:
            continue
    
    # Reverse DNS (PTR record) untuk IP A-Record pertama yang ditemukan
    if results['A']:
        for ip in results['A']:
            try:
                ptr = resolver.resolve_address(ip)
                if ptr:
                    results['PTR'] = [str(p).rstrip('.') for p in ptr]
                    break
            except Exception:
                pass
    
    return results

# ==========================================
# TESTING UNIT
# ==========================================
if __name__ == '__main__':
    print("=" * 50)
    print("DNS LOOKUP - TESTING")
    print("=" * 50)
    
    test_domain = "https://google.com/search"  # Menguji sanitasi URL
    print(f"[*] Checking DNS for: {test_domain}")
    
    results = get_dns_records(test_domain)
    
    if 'error' in results:
        print(f"[!] Error: {results['error']}")
    else:
        for record_type, records in results.items():
            if records:
                print(f"\n[*] {record_type} records:")
                for r in records:
                    print(f"    - {r}")
    
    print("\n[*] Selesai.")