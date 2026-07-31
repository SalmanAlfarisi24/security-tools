import hashlib
import os
import json
import time
from datetime import datetime

# ==========================================
# FUNGSI HASH FILE
# ==========================================
def get_file_hash(file_path, algorithm='sha256', chunk_size=8192):
    """
    Dapatkan hash dari file.
    
    Args:
        file_path (str): Path file
        algorithm (str): Algoritma hash (md5, sha1, sha256, sha512)
        chunk_size (int): Ukuran chunk untuk baca file
    
    Returns:
        dict: Detail hasil hash file
    """
    result = {
        'file': file_path,
        'hash': '',
        'algorithm': algorithm,
        'size': 0,
        'modified': '',
        'error': None
    }
    
    if not file_path or not os.path.exists(file_path):
        result['error'] = 'File not found'
        return result
    
    if not os.path.isfile(file_path):
        result['error'] = 'Path is not a file'
        return result
    
    try:
        result['size'] = os.path.getsize(file_path)
        result['modified'] = datetime.fromtimestamp(os.path.getmtime(file_path)).strftime('%Y-%m-%d %H:%M:%S')
    except Exception as e:
        result['error'] = f'Permission/Read Error: {str(e)}'
        return result
    
    try:
        hash_func = getattr(hashlib, algorithm.lower())
    except AttributeError:
        result['error'] = f'Algorithm {algorithm} not supported'
        return result
    
    hasher = hash_func()
    
    try:
        with open(file_path, 'rb') as f:
            while chunk := f.read(chunk_size):
                hasher.update(chunk)
        result['hash'] = hasher.hexdigest().lower()
    except Exception as e:
        result['error'] = str(e)
    
    return result

# ==========================================
# FUNGSI VERIFIKASI INTEGRITAS
# ==========================================
def verify_integrity(file_path, expected_hash, algorithm='sha256'):
    """
    Verifikasi integritas file dengan membandingkan hash.
    
    Args:
        file_path (str): Path file
        expected_hash (str): Hash yang diharapkan
        algorithm (str): Algoritma hash
    
    Returns:
        dict: Hasil perbandingan hash
    """
    result = {
        'file': file_path,
        'expected_hash': expected_hash.strip() if expected_hash else '',
        'actual_hash': '',
        'algorithm': algorithm,
        'verified': False,
        'message': '',
        'error': None
    }
    
    if not expected_hash:
        result['error'] = 'Expected hash tidak boleh kosong'
        result['message'] = 'Error: Expected hash tidak boleh kosong'
        return result

    # Dapatkan hash file
    hash_result = get_file_hash(file_path, algorithm)
    
    if hash_result.get('error'):
        result['error'] = hash_result['error']
        result['message'] = f"Error: {hash_result['error']}"
        return result
    
    result['actual_hash'] = hash_result['hash']
    
    # Bandingkan hash dengan mengabaikan kapitalisasi huruf (case-insensitive)
    if result['actual_hash'].lower() == expected_hash.strip().lower():
        result['verified'] = True
        result['message'] = '✅ File integrity verified successfully'
    else:
        result['verified'] = False
        result['message'] = '❌ File integrity check failed - hash mismatch'
    
    return result

# ==========================================
# FUNGSI MONITORING (BASELINE)
# ==========================================
def create_baseline(directory, output_file='baseline.json', algorithm='sha256'):
    """
    Buat baseline hash untuk semua file dalam direktori.
    
    Args:
        directory (str): Path direktori
        output_file (str): File output untuk baseline
        algorithm (str): Algoritma hash
    
    Returns:
        dict: Hasil pembuatan baseline
    """
    baseline = {
        'directory': directory,
        'algorithm': algorithm,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'files': {}
    }
    
    if not directory or not os.path.exists(directory):
        return {'error': 'Directory not found'}
    
    if not os.path.isdir(directory):
        return {'error': 'Path is not a directory'}
    
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            rel_path = os.path.relpath(file_path, directory)
            
            try:
                hash_result = get_file_hash(file_path, algorithm)
                if not hash_result.get('error'):
                    baseline['files'][rel_path] = {
                        'hash': hash_result['hash'],
                        'size': hash_result['size'],
                        'modified': hash_result['modified']
                    }
            except Exception:
                continue
    
    # Simpan baseline
    try:
        with open(output_file, 'w') as f:
            json.dump(baseline, f, indent=2)
        baseline['output_file'] = output_file
    except Exception as e:
        baseline['error'] = str(e)
    
    return baseline

def check_integrity(baseline_file='baseline.json'):
    """
    Periksa integritas file berdasarkan baseline.
    
    Args:
        baseline_file (str): File baseline JSON
    
    Returns:
        dict: Laporan integritas direktori
    """
    result = {
        'baseline': {},
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'changed_files': [],
        'new_files': [],
        'deleted_files': [],
        'summary': {}
    }
    
    # Load baseline
    try:
        with open(baseline_file, 'r') as f:
            baseline = json.load(f)
    except FileNotFoundError:
        return {'error': f'Baseline file not found: {baseline_file}'}
    except json.JSONDecodeError:
        return {'error': f'Invalid JSON in baseline file: {baseline_file}'}
    
    result['baseline'] = baseline
    
    directory = baseline.get('directory')
    algorithm = baseline.get('algorithm', 'sha256')
    
    if not directory or not os.path.exists(directory):
        return {'error': f'Directory not found: {directory}'}
    
    # Dapatkan file saat ini
    current_files = {}
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            rel_path = os.path.relpath(file_path, directory)
            
            try:
                hash_result = get_file_hash(file_path, algorithm)
                if not hash_result.get('error'):
                    current_files[rel_path] = {
                        'hash': hash_result['hash'],
                        'size': hash_result['size'],
                        'modified': hash_result['modified']
                    }
            except Exception:
                continue
    
    baseline_files = set(baseline.get('files', {}).keys())
    current_files_set = set(current_files.keys())
    
    # Cari file berubah
    for file in baseline_files & current_files_set:
        if baseline['files'][file]['hash'] != current_files[file]['hash']:
            result['changed_files'].append({
                'file': file,
                'old_hash': baseline['files'][file]['hash'],
                'new_hash': current_files[file]['hash']
            })
    
    # Cari file baru
    for file in current_files_set - baseline_files:
        result['new_files'].append({
            'file': file,
            'hash': current_files[file]['hash'],
            'size': current_files[file]['size']
        })
    
    # Cari file hilang
    for file in baseline_files - current_files_set:
        result['deleted_files'].append({
            'file': file,
            'hash': baseline['files'][file]['hash']
        })
    
    result['summary'] = {
        'total_files': len(baseline_files),
        'current_files': len(current_files_set),
        'changed': len(result['changed_files']),
        'new': len(result['new_files']),
        'deleted': len(result['deleted_files']),
        'status': '✅ Integrity OK' if len(result['changed_files']) == 0 and len(result['deleted_files']) == 0 else '⚠️ Integrity Violation Detected'
    }
    
    return result

# ==========================================
# TESTING UNIT
# ==========================================
if __name__ == '__main__':
    print("=" * 50)
    print("FILE INTEGRITY CHECKER - TESTING")
    print("=" * 50)
    
    test_file = __file__
    print(f"\n[*] Testing file: {test_file}")
    
    hash_result = get_file_hash(test_file)
    print(f"    Hash: {hash_result['hash']}")
    print(f"    Size: {hash_result['size']} bytes")
    
    import tempfile
    
    temp_dir = tempfile.mkdtemp()
    test_file2 = os.path.join(temp_dir, 'test.txt')
    with open(test_file2, 'w') as f:
        f.write('Hello World')
    
    print(f"\n[*] Creating baseline for: {temp_dir}")
    baseline_result = create_baseline(temp_dir, os.path.join(temp_dir, 'baseline.json'))
    if 'error' in baseline_result:
        print(f"    [!] Error: {baseline_result['error']}")
    else:
        print(f"    Baseline created: {baseline_result['output_file']}")
        print(f"    Files tracked: {len(baseline_result['files'])}")
    
    with open(test_file2, 'w') as f:
        f.write('Hello World Modified')
    
    print(f"\n[*] Checking integrity...")
    check_result = check_integrity(os.path.join(temp_dir, 'baseline.json'))
    if 'error' in check_result:
        print(f"    [!] Error: {check_result['error']}")
    else:
        print(f"    Status: {check_result['summary']['status']}")
        print(f"    Changed files: {len(check_result['changed_files'])}")
        if check_result['changed_files']:
            for f in check_result['changed_files']:
                print(f"      - {f['file']}: {f['old_hash'][:8]} -> {f['new_hash'][:8]}")
    
    print("\n[*] Selesai.")