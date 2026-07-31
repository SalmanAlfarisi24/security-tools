from flask import Flask, render_template, request, jsonify, session
import os
import time
import tempfile

app = Flask(__name__)
app.secret_key = 'security-tools-secret-key-change-in-production'

# ==========================================
# IMPORT MODULES
# ==========================================
from modules.subdomain import scan_subdomains
from modules.portscan import scan_ports
from modules.hashcracker import crack_hash
from modules.dirbrute import brute_directories
from modules.wifiscan import scan_wifi
from modules.emailcheck import validate_email
from modules.loganalyzer import analyze_log
from modules.dns_lookup import get_dns_records
from modules.whois_lookup import get_whois
from modules.http_headers import get_headers
from modules.ssl_checker import get_ssl_info
from modules.ping_trace import ping_host, traceroute_host
from modules.host_discovery import discover_hosts, get_local_ip
from modules.hash_generator import generate_hash, generate_file_hash
from modules.file_integrity import get_file_hash, verify_integrity, create_baseline, check_integrity
from modules.password_strength import check_password_strength
from modules.system_info import get_system_info

# ==========================================
# ROUTE DASHBOARD
# ==========================================
@app.route('/')
def index():
    return render_template('index_new.html')

# ==========================================
# BASIC TOOLS (EXISTING)
# ==========================================
@app.route('/subdomain', methods=['GET', 'POST'])
def subdomain_tool():
    if request.method == 'POST':
        domain = request.form.get('domain', '').strip()
        if not domain:
            return render_template('subdomain.html', error='Domain tidak boleh kosong!')
        start = time.time()
        results, total, found = scan_subdomains(domain)
        elapsed = time.time() - start
        return render_template('subdomain.html', domain=domain, results=results, total=total, found=found, elapsed=f"{elapsed:.2f}")
    return render_template('subdomain.html')

@app.route('/portscan', methods=['GET', 'POST'])
def portscan_tool():
    if request.method == 'POST':
        target = request.form.get('target', '').strip()
        if not target:
            return render_template('portscan.html', error='Target tidak boleh kosong!')
        ports_str = request.form.get('ports', '').strip()
        ports = [int(p.strip()) for p in ports_str.split(',') if p.strip().isdigit()] if ports_str else None
        timeout = float(request.form.get('timeout', 1.0))
        result = scan_ports(target, ports, timeout)
        return render_template('portscan.html', target=target, results=result['results'], open_count=result['open_count'], closed_count=result['closed_count'], error=result['error'], elapsed=0)
    return render_template('portscan.html')

@app.route('/hashcrack', methods=['GET', 'POST'])
def hashcrack_tool():
    if request.method == 'POST':
        hash_type = request.form.get('hash_type', 'md5')
        hash_value = request.form.get('hash_value', '').strip()
        wordlist = request.form.get('wordlist', '').strip()
        if not hash_value:
            return render_template('hashcracker.html', error='Hash tidak boleh kosong!')
        wordlist_list = [w.strip() for w in wordlist.split(',')] if wordlist else None
        result = crack_hash(hash_type, hash_value, wordlist_list)
        return render_template('hashcracker.html', result=result, hash_value=hash_value, hash_type=hash_type)
    return render_template('hashcracker.html')

@app.route('/dirbrute', methods=['GET', 'POST'])
def dirbrute_tool():
    if request.method == 'POST':
        url = request.form.get('url', '').strip()
        wordlist = request.form.get('wordlist', '').strip()
        if not url:
            return render_template('dirbrute.html', error='URL tidak boleh kosong!')
        wordlist_list = [w.strip() for w in wordlist.split(',')] if wordlist else None
        start = time.time()
        results, found, total = brute_directories(url, wordlist_list)
        elapsed = time.time() - start
        return render_template('dirbrute.html', url=url, results=results, found=found, total=total, elapsed=f"{elapsed:.2f}")
    return render_template('dirbrute.html')

@app.route('/wifiscan', methods=['GET', 'POST'])
def wifiscan_tool():
    if request.method == 'POST':
        interface = request.form.get('interface', 'wlan0')
        duration = int(request.form.get('duration', 10))
        results = scan_wifi(interface, duration)
        return render_template('wifiscan.html', results=results, interface=interface, duration=duration)
    return render_template('wifiscan.html')

@app.route('/emailcheck', methods=['GET', 'POST'])
def emailcheck_tool():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        if not email:
            return render_template('emailcheck.html', error='Email tidak boleh kosong!')
        result = validate_email(email)
        return render_template('emailcheck.html', result=result, email=email)
    return render_template('emailcheck.html')

@app.route('/loganalyzer', methods=['GET', 'POST'])
def loganalyzer_tool():
    if request.method == 'POST':
        log_content = request.form.get('log_content', '').strip()
        if not log_content:
            return render_template('loganalyzer.html', error='Log tidak boleh kosong!')
        results = analyze_log(log_content)
        return render_template('loganalyzer.html', results=results, log_content=log_content[:500])
    return render_template('loganalyzer.html')

# ==========================================
# NEW TOOLS ROUTES
# ==========================================
@app.route('/dns_lookup', methods=['GET', 'POST'])
def dns_lookup():
    if request.method == 'POST':
        domain = request.form.get('domain', '').strip()
        if not domain:
            return render_template('dns_lookup.html', error='Domain tidak boleh kosong!')
        result = get_dns_records(domain)
        return render_template('dns_lookup.html', domain=domain, result=result)
    return render_template('dns_lookup.html')

@app.route('/whois', methods=['GET', 'POST'])
def whois_lookup():
    if request.method == 'POST':
        domain = request.form.get('domain', '').strip()
        if not domain:
            return render_template('whois_lookup.html', error='Domain tidak boleh kosong!')
        result = get_whois(domain)
        return render_template('whois_lookup.html', domain=domain, result=result)
    return render_template('whois_lookup.html')

@app.route('/http_headers', methods=['GET', 'POST'])
def http_headers():
    if request.method == 'POST':
        url = request.form.get('url', '').strip()
        if not url:
            return render_template('http_headers.html', error='URL tidak boleh kosong!')
        if not url.startswith('http'):
            url = 'https://' + url
        result = get_headers(url)
        return render_template('http_headers.html', url=url, result=result)
    return render_template('http_headers.html')

@app.route('/ssl_check', methods=['GET', 'POST'])
def ssl_check():
    if request.method == 'POST':
        hostname = request.form.get('hostname', '').strip()
        port = int(request.form.get('port', 443))
        if not hostname:
            return render_template('ssl_check.html', error='Hostname tidak boleh kosong!')
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
        ping_result = ping_host(hostname) if action in ['ping', 'both'] else None
        trace_result = traceroute_host(hostname) if action in ['trace', 'both'] else None
        return render_template('ping_trace.html', hostname=hostname, ping_result=ping_result, trace_result=trace_result, action=action)
    return render_template('ping_trace.html')

@app.route('/host_discovery', methods=['GET', 'POST'])
def host_discovery():
    if request.method == 'POST':
        ip_range = request.form.get('ip_range', '').strip()
        mask = int(request.form.get('mask', 24))
        if not ip_range:
            local_ip = get_local_ip()
            ip_range = f"{local_ip}/24"
        result = discover_hosts(ip_range, mask)
        return render_template('host_discovery.html', result=result, ip_range=ip_range)
    return render_template('host_discovery.html')

@app.route('/hash_generator', methods=['GET', 'POST'])
def hash_generator():
    if request.method == 'POST':
        mode = request.form.get('mode', 'text')
        algorithm = request.form.get('algorithm', 'md5')
        if mode == 'file':
            if 'file' not in request.files:
                return render_template('hash_generator.html', error='File tidak ditemukan!')
            file = request.files['file']
            if file.filename == '':
                return render_template('hash_generator.html', error='File tidak dipilih!')
            with tempfile.NamedTemporaryFile(delete=False, suffix='_hash') as tmp:
                file.save(tmp.name)
                result = generate_file_hash(tmp.name, algorithm)
                os.unlink(tmp.name)
            return render_template('hash_generator.html', result=result, mode='file', algorithm=algorithm)
        else:
            text = request.form.get('text', '').strip()
            if not text:
                return render_template('hash_generator.html', error='Text tidak boleh kosong!')
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
            with tempfile.NamedTemporaryFile(delete=False, suffix='_integrity') as tmp:
                file.save(tmp.name)
                result = verify_integrity(tmp.name, expected_hash, algorithm)
                os.unlink(tmp.name)
            return render_template('file_integrity.html', result=result, action='verify')
        elif action == 'baseline':
            directory = request.form.get('directory', '').strip()
            if not directory:
                return render_template('file_integrity.html', error='Directory tidak boleh kosong!')
            if not os.path.isdir(directory):
                return render_template('file_integrity.html', error='Directory tidak ditemukan!')
            algorithm = request.form.get('algorithm', 'sha256')
            baseline_file = os.path.join(directory, 'baseline.json')
            result = create_baseline(directory, baseline_file, algorithm)
            return render_template('file_integrity.html', result=result, action='baseline')
        elif action == 'check':
            baseline_file = request.form.get('baseline_file', '').strip()
            if not baseline_file:
                return render_template('file_integrity.html', error='Baseline file tidak boleh kosong!')
            if not os.path.isfile(baseline_file):
                return render_template('file_integrity.html', error='Baseline file tidak ditemukan!')
            result = check_integrity(baseline_file)
            return render_template('file_integrity.html', result=result, action='check')
    return render_template('file_integrity.html')

@app.route('/password_strength', methods=['GET', 'POST'])
def password_strength():
    if request.method == 'POST':
        password = request.form.get('password', '').strip()
        if not password:
            return render_template('password_strength.html', error='Password tidak boleh kosong!')
        result = check_password_strength(password)
        return render_template('password_strength.html', result=result)
    return render_template('password_strength.html')

@app.route('/system_info')
def system_info():
    info = get_system_info()
    return render_template('system_info.html', info=info)

# ==========================================
# JALANKAN APP
# ==========================================
if __name__ == '__main__':
    print("=" * 60)
    print("🔐 SECURITY TOOLS SUITE - COMPLETE")
    print("=" * 60)
    print("📍 http://localhost:5000")
    print("📡 Tools tersedia:")
    print("   - Subdomain Finder")
    print("   - Port Scanner")
    print("   - Hash Cracker")
    print("   - Directory Brute")
    print("   - WiFi Scanner")
    print("   - Email Validator")
    print("   - Log Analyzer")
    print("   - DNS Lookup")
    print("   - WHOIS Lookup")
    print("   - HTTP Header Analyzer")
    print("   - SSL/TLS Checker")
    print("   - Ping & Traceroute")
    print("   - Host Discovery")
    print("   - Hash Generator")
    print("   - File Integrity Checker")
    print("   - Password Strength Checker")
    print("   - System Information")
    print("=" * 60)
    app.run(debug=True, host='0.0.0.0', port=5000)