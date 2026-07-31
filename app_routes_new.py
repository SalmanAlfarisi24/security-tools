# ==========================================
# TAMBAHKAN INI KE app.py
# ==========================================

from flask import render_template, request, jsonify
import time

# ===== DNS LOOKUP =====
@app.route('/dns_lookup', methods=['GET', 'POST'])
def dns_lookup():
    from modules.dns_lookup import get_dns_records
    
    if request.method == 'POST':
        domain = request.form.get('domain', '').strip()
        if not domain:
            return render_template('dns_lookup.html', error='Domain tidak boleh kosong!')
        
        result = get_dns_records(domain)
        return render_template('dns_lookup.html', domain=domain, result=result)
    
    return render_template('dns_lookup.html')

# ===== WHOIS LOOKUP =====
@app.route('/whois', methods=['GET', 'POST'])
def whois_lookup():
    from modules.whois_lookup import get_whois
    
    if request.method == 'POST':
        domain = request.form.get('domain', '').strip()
        if not domain:
            return render_template('whois_lookup.html', error='Domain tidak boleh kosong!')
        
        result = get_whois(domain)
        return render_template('whois_lookup.html', domain=domain, result=result)
    
    return render_template('whois_lookup.html')

# ===== HTTP HEADER ANALYZER =====
@app.route('/http_headers', methods=['GET', 'POST'])
def http_headers():
    from modules.http_headers import get_headers
    
    if request.method == 'POST':
        url = request.form.get('url', '').strip()
        if not url:
            return render_template('http_headers.html', error='URL tidak boleh kosong!')
        
        if not url.startswith('http'):
            url = 'https://' + url
        
        result = get_headers(url)
        return render_template('http_headers.html', url=url, result=result)
    
    return render_template('http_headers.html')

# ===== SSL/TLS CHECKER =====
@app.route('/ssl_check', methods=['GET', 'POST'])
def ssl_check():
    from modules.ssl_checker import get_ssl_info
    
    if request.method == 'POST':
        hostname = request.form.get('hostname', '').strip()
        port = int(request.form.get('port', 443))
        
        if not hostname:
            return render_template('ssl_check.html', error='Hostname tidak boleh kosong!')
        
        result = get_ssl_info(hostname, port)
        return render_template('ssl_check.html', hostname=hostname, port=port, result=result)
    
    return render_template('ssl_check.html')

# ===== PING & TRACEROUTE =====
@app.route('/ping_trace', methods=['GET', 'POST'])
def ping_trace():
    from modules.ping_trace import ping_host, traceroute_host
    
    if request.method == 'POST':
        hostname = request.form.get('hostname', '').strip()
        action = request.form.get('action', 'ping')
        
        if not hostname:
            return render_template('ping_trace.html', error='Hostname tidak boleh kosong!')
        
        ping_result = None
        trace_result = None
        
        if action in ['ping', 'both']:
            ping_result = ping_host(hostname)
        
        if action in ['trace', 'both']:
            trace_result = traceroute_host(hostname)
        
        return render_template('ping_trace.html', 
                              hostname=hostname, 
                              ping_result=ping_result, 
                              trace_result=trace_result,
                              action=action)
    
    return render_template('ping_trace.html')

# ===== HOST DISCOVERY =====
@app.route('/host_discovery', methods=['GET', 'POST'])
def host_discovery():
    from modules.host_discovery import discover_hosts, get_local_ip
    
    if request.method == 'POST':
        ip_range = request.form.get('ip_range', '').strip()
        mask = int(request.form.get('mask', 24))
        
        if not ip_range:
            local_ip = get_local_ip()
            ip_range = f"{local_ip}/24"
        
        result = discover_hosts(ip_range, mask)
        return render_template('host_discovery.html', result=result, ip_range=ip_range)
    
    return render_template('host_discovery.html')

# ===== HASH GENERATOR =====
@app.route('/hash_generator', methods=['GET', 'POST'])
def hash_generator():
    from modules.hash_generator import generate_hash, generate_file_hash
    
    if request.method == 'POST':
        text = request.form.get('text', '').strip()
        algorithm = request.form.get('algorithm', 'md5')
        mode = request.form.get('mode', 'text')  # text or file
        
        if mode == 'file':
            # File upload handling
            if 'file' not in request.files:
                return render_template('hash_generator.html', error='File tidak ditemukan!')
            
            file = request.files['file']
            if file.filename == '':
                return render_template('hash_generator.html', error='File tidak dipilih!')
            
            # Save file temporarily
            import tempfile
            import os
            with tempfile.NamedTemporaryFile(delete=False, suffix='_hash') as tmp:
                file.save(tmp.name)
                result = generate_file_hash(tmp.name, algorithm)
                os.unlink(tmp.name)
            
            return render_template('hash_generator.html', result=result, mode='file', algorithm=algorithm)
        
        else:
            if not text:
                return render_template('hash_generator.html', error='Text tidak boleh kosong!')
            
            result = generate_hash(text, algorithm)
            return render_template('hash_generator.html', result=result, mode='text', algorithm=algorithm, text=text)
    
    return render_template('hash_generator.html')

# ===== FILE INTEGRITY CHECKER =====
@app.route('/file_integrity', methods=['GET', 'POST'])
def file_integrity():
    from modules.file_integrity import get_file_hash, verify_integrity, create_baseline, check_integrity
    import tempfile
    import os
    
    if request.method == 'POST':
        action = request.form.get('action', 'verify')
        
        if action == 'verify':
            # Verify single file
            if 'file' not in request.files:
                return render_template('file_integrity.html', error='File tidak ditemukan!')
            
            file = request.files['file']
            if file.filename == '':
                return render_template('file_integrity.html', error='File tidak dipilih!')
            
            expected_hash = request.form.get('expected_hash', '').strip()
            algorithm = request.form.get('algorithm', 'sha256')
            
            if not expected_hash:
                return render_template('file_integrity.html', error='Expected hash tidak boleh kosong!')
            
            # Save file temporarily
            with tempfile.NamedTemporaryFile(delete=False, suffix='_integrity') as tmp:
                file.save(tmp.name)
                result = verify_integrity(tmp.name, expected_hash, algorithm)
                os.unlink(tmp.name)
            
            return render_template('file_integrity.html', result=result, action='verify')
        
        elif action == 'baseline':
            # Create baseline
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
            # Check integrity
            baseline_file = request.form.get('baseline_file', '').strip()
            if not baseline_file:
                return render_template('file_integrity.html', error='Baseline file tidak boleh kosong!')
            
            if not os.path.isfile(baseline_file):
                return render_template('file_integrity.html', error='Baseline file tidak ditemukan!')
            
            result = check_integrity(baseline_file)
            return render_template('file_integrity.html', result=result, action='check')
    
    return render_template('file_integrity.html')

# ===== PASSWORD STRENGTH CHECKER =====
@app.route('/password_strength', methods=['GET', 'POST'])
def password_strength():
    from modules.password_strength import check_password_strength
    
    if request.method == 'POST':
        password = request.form.get('password', '').strip()
        
        if not password:
            return render_template('password_strength.html', error='Password tidak boleh kosong!')
        
        result = check_password_strength(password)
        return render_template('password_strength.html', result=result)
    
    return render_template('password_strength.html')

# ===== SYSTEM INFORMATION =====
@app.route('/system_info')
def system_info():
    from modules.system_info import get_system_info
    
    info = get_system_info()
    return render_template('system_info.html', info=info)

# ==========================================
# UPDATE ROUTE INDEX
# ==========================================
@app.route('/')
def index():
    return render_template('index_new.html')