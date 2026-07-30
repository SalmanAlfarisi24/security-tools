from flask import Flask, render_template, request, jsonify
import os
import time

# ==========================================
# INISIALISASI FLASK
# ==========================================
app = Flask(__name__)
app.secret_key = 'security-tools-secret-key-change-in-production'

# ==========================================
# ROUTE DASHBOARD
# ==========================================
@app.route('/')
def index():
    """Halaman utama dashboard"""
    return render_template('index.html')

# ==========================================
# ROUTE SUBDOMAIN FINDER
# ==========================================
@app.route('/subdomain', methods=['GET', 'POST'])
def subdomain_tool():
    """Halaman Subdomain Finder"""
    if request.method == 'POST':
        domain = request.form.get('domain', '').strip()
        if not domain:
            return render_template('subdomain.html', error='Domain tidak boleh kosong!')
        
        from modules.subdomain import scan_subdomains
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

# ==========================================
# ROUTE PORT SCANNER
# ==========================================
@app.route('/portscan', methods=['GET', 'POST'])
def portscan_tool():
    """Halaman Port Scanner"""
    if request.method == 'POST':
        target = request.form.get('target', '').strip()
        ports_raw = request.form.get('ports', '').strip()
        timeout_val = float(request.form.get('timeout', 1.0))
        
        if not target:
            return render_template('portscan.html', error='Target IP/domain tidak boleh kosong!')
        
        # Parse custom ports jika diisi oleh user
        ports = None
        if ports_raw:
            try:
                ports = [int(p.strip()) for p in ports_raw.split(',') if p.strip().isdigit()]
            except ValueError:
                ports = None

        from modules.portscan import scan_ports
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

# ==========================================
# ROUTE HASH CRACKER
# ==========================================
@app.route('/hashcrack', methods=['GET', 'POST'])
def hashcrack_tool():
    """Halaman Hash Cracker"""
    if request.method == 'POST':
        hash_type = request.form.get('hash_type', 'md5')
        hash_value = request.form.get('hash_value', '').strip()
        wordlist_raw = request.form.get('wordlist', '').strip()
        
        if not hash_value:
            return render_template('hashcrack.html', error='Hash tidak boleh kosong!')
        
        # Format string koma menjadi list
        wordlist = [w.strip() for w in wordlist_raw.split(',') if w.strip()] if wordlist_raw else None

        from modules.hashcrack import crack_hash
        result = crack_hash(hash_type, hash_value, wordlist)
        
        return render_template(
            'hashcrack.html',
            result=result,
            hash_value=hash_value,
            hash_type=hash_type
        )
    
    return render_template('hashcrack.html')

# ==========================================
# ROUTE DIRECTORY BRUTE
# ==========================================
@app.route('/dirbrute', methods=['GET', 'POST'])
def dirbrute_tool():
    """Halaman Directory Brute"""
    if request.method == 'POST':
        url = request.form.get('url', '').strip()
        wordlist_raw = request.form.get('wordlist', '').strip()
        
        if not url:
            return render_template('dirbrute.html', error='URL tidak boleh kosong!')
        
        # Format string koma menjadi list
        wordlist = [w.strip() for w in wordlist_raw.split(',') if w.strip()] if wordlist_raw else None

        from modules.dirbrute import brute_directories
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

# ==========================================
# ROUTE WIFI SCANNER
# ==========================================
@app.route('/wifiscan', methods=['GET', 'POST'])
def wifiscan_tool():
    """Halaman WiFi Scanner"""
    if request.method == 'POST':
        interface = request.form.get('interface', 'wlan0')
        duration = int(request.form.get('duration', 10))
        
        from modules.wifiscan import scan_wifi
        results = scan_wifi(interface, duration)
        
        return render_template(
            'wifiscan.html',
            results=results,
            interface=interface,
            duration=duration
        )
    
    return render_template('wifiscan.html')

# ==========================================
# ROUTE EMAIL VALIDATOR
# ==========================================
@app.route('/emailcheck', methods=['GET', 'POST'])
def emailcheck_tool():
    """Halaman Email Validator"""
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        if not email:
            return render_template('emailcheck.html', error='Email tidak boleh kosong!')
        
        from modules.emailcheck import validate_email
        result = validate_email(email)
        
        return render_template(
            'emailcheck.html',
            result=result,
            email=email
        )
    
    return render_template('emailcheck.html')

# ==========================================
# ROUTE LOG ANALYZER
# ==========================================
@app.route('/loganalyzer', methods=['GET', 'POST'])
def loganalyzer_tool():
    """Halaman Log Analyzer"""
    if request.method == 'POST':
        log_content = request.form.get('log_content', '').strip()
        if not log_content:
            return render_template('loganalyzer.html', error='Log tidak boleh kosong!')
        
        from modules.loganalyzer import analyze_log
        results = analyze_log(log_content)
        
        return render_template(
            'loganalyzer.html',
            results=results,
            log_content=log_content
        )
    
    return render_template('loganalyzer.html')

# ==========================================
# JALANKAN APP
# ==========================================
if __name__ == '__main__':
    print("=" * 50)
    print("🔐 SECURITY TOOLS DASHBOARD")
    print("=" * 50)
    print("📍 http://localhost:5000")
    print("=" * 50)
    app.run(debug=True, host='0.0.0.0', port=5000)