import os
import time
import tempfile
from flask import Flask, render_template, request, jsonify, session, redirect, url_for

# ==========================================
# INISIALISASI FLASK
# ==========================================
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'security-tools-secret-key-change-in-production')

# ==========================================
# IMPORT MODULES DENGAN FALLBACK SAFE
# ==========================================
try:
    from modules.subdomain import scan_subdomains
except ImportError:
    scan_subdomains = None

try:
    from modules.portscan import scan_ports
except ImportError:
    scan_ports = None

try:
    from modules.hashcrack import crack_hash
except ImportError:
    try:
        from modules.hashcracker import crack_hash
    except ImportError:
        crack_hash = None

try:
    from modules.dirbrute import brute_directories
except ImportError:
    brute_directories = None

try:
    from modules.wifiscan import scan_wifi
except ImportError:
    scan_wifi = None

try:
    from modules.emailcheck import validate_email
except ImportError:
    validate_email = None

try:
    from modules.loganalyzer import analyze_log
except ImportError:
    try:
        from modules.loganalyzer import analyze_logs as analyze_log
    except ImportError:
        analyze_log = None

try:
    from modules.dns_lookup import get_dns_records
except ImportError:
    get_dns_records = None

try:
    from modules.whois_lookup import get_whois
except ImportError:
    get_whois = None

try:
    from modules.http_headers import get_headers
except ImportError:
    get_headers = None

try:
    from modules.ssl_checker import get_ssl_info
except ImportError:
    get_ssl_info = None

try:
    from modules.ping_trace import ping_host, traceroute_host
except ImportError:
    ping_host, traceroute_host = None, None

try:
    from modules.host_discovery import discover_hosts, get_local_ip
except ImportError:
    discover_hosts, get_local_ip = None, None

try:
    from modules.hash_generator import generate_hash, generate_file_hash
except ImportError:
    generate_hash, generate_file_hash = None, None

try:
    from modules.file_integrity import get_file_hash, verify_integrity, create_baseline, check_integrity
except ImportError:
    get_file_hash, verify_integrity, create_baseline, check_integrity = None, None, None, None

try:
    from modules.password_strength import check_password_strength
except ImportError:
    check_password_strength = None

try:
    from modules.system_info import get_system_info
except ImportError:
    get_system_info = None


# ==========================================
# ROUTE DASHBOARD
# ==========================================
@app.route('/')
def index():
    """Halaman utama dashboard"""
    return render_template('index.html')


# ==========================================
# ROUTE NETWORK & RECON TOOLS
# ==========================================
@app.route('/subdomain', methods=['GET', 'POST'])
def subdomain_tool():
    if request.method == 'POST':
        domain = request.form.get('domain', '').strip()
        if not domain:
            return render_template('subdomain.html', error='Domain tidak boleh kosong!')
        
        if not scan_subdomains:
            return render_template('subdomain.html', error='Modul subdomain tidak tersedia!')

        start = time.time()
        results, total, found = scan_subdomains(domain)
        elapsed = time.time() - start
        
        return render_template(
            'subdomain.html',
            domain=domain,
            results=results,
            total=total,
            found=found,
            elapsed=f"{elapsed:.2f}"
        )
    return render_template('subdomain.html')


@app.route('/portscan', methods=['GET', 'POST'])
def portscan_tool():
    if request.method == 'POST':
        target = request.form.get('target', '').strip()
        ports_raw = request.form.get('ports', '').strip()
        
        try:
            timeout_val = float(request.form.get('timeout', 1.0))
        except (ValueError, TypeError):
            timeout_val = 1.0

        if not target:
            return render_template('portscan.html', error='Target IP/domain tidak boleh kosong!')

        ports = None
        if ports_raw:
            ports = [int(p.strip()) for p in ports_raw.split(',') if p.strip().isdigit()]

        if not scan_ports:
            return render_template('portscan.html', error='Modul portscan tidak tersedia!')

        start = time.time()
        scan_res = scan_ports(target, ports=ports, timeout=timeout_val)
        elapsed = time.time() - start

        return render_template(
            'portscan.html',
            target=scan_res.get('target', target),
            results=scan_res.get('results', []),
            open_count=scan_res.get('open_count', 0),
            closed_count=scan_res.get('closed_count', 0),
            error=scan_res.get('error'),
            elapsed=f"{elapsed:.2f}"
        )
    return render_template('portscan.html')


@app.route('/dirbrute', methods=['GET', 'POST'])
def dirbrute_tool():
    if request.method == 'POST':
        url = request.form.get('url', '').strip()
        wordlist_raw = request.form.get('wordlist', '').strip()

        if not url:
            return render_template('dirbrute.html', error='URL tidak boleh kosong!')

        wordlist = [w.strip() for w in wordlist_raw.split(',') if w.strip()] if wordlist_raw else None

        if not brute_directories:
            return render_template('dirbrute.html', error='Modul dirbrute tidak tersedia!')

        start = time.time()
        results, found, total = brute_directories(url, wordlist)
        elapsed = time.time() - start

        return render_template(
            'dirbrute.html',
            url=url,
            results=results,
            found=found,
            total=total,
            elapsed=f"{elapsed:.2f}"
        )
    return render_template('dirbrute.html')


@app.route('/dns_lookup', methods=['GET', 'POST'])
def dns_lookup():
    if request.method == 'POST':
        domain = request.form.get('domain', '').strip()
        if not domain:
            return render_template('dns_lookup.html', error='Domain tidak boleh kosong!')
        
        if not get_dns_records:
            return render_template('dns_lookup.html', error='Modul dns_lookup tidak tersedia!')

        result = get_dns_records(domain)
        return render_template('dns_lookup.html', domain=domain, result=result)
    return render_template('dns_lookup.html')


@app.route('/whois', methods=['GET', 'POST'])
def whois_lookup():
    if request.method == 'POST':
        domain = request.form.get('domain', '').strip()
        if not domain:
            return render_template('whois_lookup.html', error='Domain tidak boleh kosong!')
        
        if not get_whois:
            return render_template('whois_lookup.html', error='Modul whois_lookup tidak tersedia!')

        result = get_whois(domain)
        return render_template('whois_lookup.html', domain=domain, result=result)
    return render_template('whois_lookup.html')


@app.route('/http_headers', methods=['GET', 'POST'])
def http_headers():
    if request.method == 'POST':
        url = request.form.get('url', '').strip()
        if not url:
            return render_template('http_headers.html', error='URL tidak boleh kosong!')

        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url

        if not get_headers:
            return render_template('http_headers.html', error='Modul http_headers tidak tersedia!')

        result = get_headers(url)
        return render_template('http_headers.html', url=url, result=result)
    return render_template('http_headers.html')


@app.route('/ssl_check', methods=['GET', 'POST'])
def ssl_check():
    if request.method == 'POST':
        hostname = request.form.get('hostname', '').strip()
        try:
            port = int(request.form.get('port', 443))
        except (ValueError, TypeError):
            port = 443

        if not hostname:
            return render_template('ssl_check.html', error='Hostname tidak boleh kosong!')

        if not get_ssl_info:
            return render_template('ssl_check.html', error='Modul ssl_checker tidak tersedia!')

        result = get_ssl_info(hostname, port)
        return render_template('ssl_check.html', hostname=hostname, port=port, result=result)
    return render_template('ssl_check.html')


@app.route('/ping_trace', methods=['GET', 'POST'])
def ping_trace():
    if request.method == 'POST':
        hostname = request.form.get('hostname', '').strip()
        action = request.form.get('action', 'both')

        if not hostname:
            return render_template('ping_trace.html', error='Hostname tidak boleh kosong!')

        if not ping_host or not traceroute_host:
            return render_template('ping_trace.html', error='Modul ping_trace tidak tersedia!')

        ping_result = ping_host(hostname) if action in ['ping', 'both'] else None
        trace_result = traceroute_host(hostname) if action in ['trace', 'both'] else None

        return render_template(
            'ping_trace.html',
            hostname=hostname,
            ping_result=ping_result,
            trace_result=trace_result,
            action=action
        )
    return render_template('ping_trace.html')


@app.route('/host_discovery', methods=['GET', 'POST'])
def host_discovery():
    if request.method == 'POST':
        ip_range = request.form.get('ip_range', '').strip()
        try:
            mask = int(request.form.get('mask', 24))
        except (ValueError, TypeError):
            mask = 24

        if not discover_hosts:
            return render_template('host_discovery.html', error='Modul host_discovery tidak tersedia!')

        if not ip_range and get_local_ip:
            local_ip = get_local_ip()
            ip_range = f"{local_ip}/24"

        result = discover_hosts(ip_range, mask)
        return render_template('host_discovery.html', result=result, ip_range=ip_range)
    return render_template('host_discovery.html')


@app.route('/wifiscan', methods=['GET', 'POST'])
def wifiscan_tool():
    if request.method == 'POST':
        interface = request.form.get('interface', 'wlan0').strip()
        try:
            duration = int(request.form.get('duration', 10))
        except (ValueError, TypeError):
            duration = 10

        if not scan_wifi:
            return render_template('wifiscan.html', error='Modul wifiscan tidak tersedia!')

        results = scan_wifi(interface, duration)
        return render_template('wifiscan.html', results=results, interface=interface, duration=duration)
    return render_template('wifiscan.html')


# ==========================================
# ROUTE CRYPTO & SECURITY ANALYSIS TOOLS
# ==========================================
@app.route('/hashcrack', methods=['GET', 'POST'])
def hashcrack_tool():
    if request.method == 'POST':
        hash_type = request.form.get('hash_type', 'md5').strip()
        hash_value = request.form.get('hash_value', '').strip()
        wordlist_raw = request.form.get('wordlist', '').strip()

        if not hash_value:
            return render_template('hashcrack.html', error='Hash tidak boleh kosong!')

        wordlist = [w.strip() for w in wordlist_raw.split(',') if w.strip()] if wordlist_raw else None

        if not crack_hash:
            return render_template('hashcrack.html', error='Modul hashcrack tidak tersedia!')

        result = crack_hash(hash_type, hash_value, wordlist)
        return render_template(
            'hashcrack.html',
            result=result,
            hash_value=hash_value,
            hash_type=hash_type
        )
    return render_template('hashcrack.html')


@app.route('/hash_generator', methods=['GET', 'POST'])
def hash_generator():
    if request.method == 'POST':
        mode = request.form.get('mode', 'text')
        algorithm = request.form.get('algorithm', 'md5')

        if not generate_hash or not generate_file_hash:
            return render_template('hash_generator.html', error='Modul hash_generator tidak tersedia!')

        if mode == 'file':
            if 'file' not in request.files:
                return render_template('hash_generator.html', error='File tidak ditemukan!')
            file = request.files['file']
            if file.filename == '':
                return render_template('hash_generator.html', error='File tidak dipilih!')

            # Handling file sementara secara aman
            tmp_path = None
            try:
                with tempfile.NamedTemporaryFile(delete=False, suffix='_hash') as tmp:
                    file.save(tmp.name)
                    tmp_path = tmp.name

                result = generate_file_hash(tmp_path, algorithm)
            finally:
                if tmp_path and os.path.exists(tmp_path):
                    os.unlink(tmp_path)

            return render_template('hash_generator.html', result=result, mode='file', algorithm=algorithm)
        else:
            text = request.form.get('text', '').strip()
            if not text:
                return render_template('hash_generator.html', error='Teks tidak boleh kosong!')

            result = generate_hash(text, algorithm)
            return render_template('hash_generator.html', result=result, mode='text', algorithm=algorithm, text=text)
    return render_template('hash_generator.html')


@app.route('/file_integrity', methods=['GET', 'POST'])
def file_integrity():
    if request.method == 'POST':
        action = request.form.get('action', 'verify')

        if action == 'verify':
            if 'file' not in request.files:
                return render_template('file_integrity.html', error='File tidak ditemukan!')
            file = request.files['file']
            if file.filename == '':
                return render_template('file_integrity.html', error='File tidak dipilih!')

            expected_hash = request.form.get('expected_hash', '').strip()
            algorithm = request.form.get('algorithm', 'sha256')

            if not expected_hash:
                return render_template('file_integrity.html', error='Expected hash tidak boleh kosong!')

            if not verify_integrity:
                return render_template('file_integrity.html', error='Modul file_integrity tidak tersedia!')

            tmp_path = None
            try:
                with tempfile.NamedTemporaryFile(delete=False, suffix='_integrity') as tmp:
                    file.save(tmp.name)
                    tmp_path = tmp.name

                result = verify_integrity(tmp_path, expected_hash, algorithm)
            finally:
                if tmp_path and os.path.exists(tmp_path):
                    os.unlink(tmp_path)

            return render_template('file_integrity.html', result=result, action='verify')

        elif action == 'baseline':
            directory = request.form.get('directory', '').strip()
            algorithm = request.form.get('algorithm', 'sha256')

            if not directory or not os.path.isdir(directory):
                return render_template('file_integrity.html', error='Direktori tidak valid atau tidak ditemukan!')

            if not create_baseline:
                return render_template('file_integrity.html', error='Modul file_integrity tidak tersedia!')

            baseline_file = os.path.join(directory, 'baseline.json')
            result = create_baseline(directory, baseline_file, algorithm)
            return render_template('file_integrity.html', result=result, action='baseline')

        elif action == 'check':
            baseline_file = request.form.get('baseline_file', '').strip()

            if not baseline_file or not os.path.isfile(baseline_file):
                return render_template('file_integrity.html', error='File baseline tidak valid atau tidak ditemukan!')

            if not check_integrity:
                return render_template('file_integrity.html', error='Modul file_integrity tidak tersedia!')

            result = check_integrity(baseline_file)
            return render_template('file_integrity.html', result=result, action='check')

    return render_template('file_integrity.html')


@app.route('/password_strength', methods=['GET', 'POST'])
def password_strength():
    if request.method == 'POST':
        password = request.form.get('password', '').strip()
        if not password:
            return render_template('password_strength.html', error='Password tidak boleh kosong!')

        if not check_password_strength:
            return render_template('password_strength.html', error='Modul password_strength tidak tersedia!')

        result = check_password_strength(password)
        return render_template('password_strength.html', result=result)
    return render_template('password_strength.html')


# ==========================================
# ROUTE VALIDATION & AUDITING TOOLS
# ==========================================
@app.route('/emailcheck', methods=['GET', 'POST'])
def emailcheck_tool():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        if not email:
            return render_template('emailcheck.html', error='Email tidak boleh kosong!')

        if not validate_email:
            return render_template('emailcheck.html', error='Modul emailcheck tidak tersedia!')

        result = validate_email(email)
        return render_template('emailcheck.html', result=result, email=email)
    return render_template('emailcheck.html')


@app.route('/loganalyzer', methods=['GET', 'POST'])
def loganalyzer_tool():
    if request.method == 'POST':
        log_content = request.form.get('log_content', '').strip()
        if not log_content:
            return render_template('loganalyzer.html', error='Log content tidak boleh kosong!')

        if not analyze_log:
            return render_template('loganalyzer.html', error='Modul loganalyzer tidak tersedia!')

        results = analyze_log(log_content)
        return render_template('loganalyzer.html', results=results, log_content=log_content[:500])

    return render_template('loganalyzer.html', log_content='', results=None, stats=None, error=None)


@app.route('/system_info')
def system_info():
    if not get_system_info:
        return render_template('system_info.html', error='Modul system_info tidak tersedia!')

    info = get_system_info()
    return render_template('system_info.html', info=info)


# ==========================================
# JALANKAN SERVING FLASK
# ==========================================
if __name__ == '__main__':
    print("=" * 60)
    print("🔐 SECURITY TOOLS SUITE - UNIFIED APP")
    print("=" * 60)
    print("📍 http://localhost:5000")
    print("=" * 60)
    app.run(debug=True, host='0.0.0.0', port=5000)