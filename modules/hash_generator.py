import hashlib
import bcrypt
import base64
import os

# ==========================================
# FUNGSI GENERATE HASH DARI TEKS
# ==========================================
def generate_hash(text, algorithm='md5', salt=None):
    """
    Generate hash dari teks dengan berbagai algoritma.
    
    Args:
        text (str): Teks yang akan di-hash
        algorithm (str): Algoritma hash (md5, sha1, sha256, sha512, bcrypt, base64)
        salt (str): Salt untuk bcrypt (opsional)
    
    Returns:
        dict: Hasil pembuatan hash
    """
    if text is None:
        return {'error': 'Teks input tidak boleh kosong'}
    
    algorithm = str(algorithm).lower().strip()
    
    result = {
        'algorithm': algorithm,
        'input': text,
        'hash': '',
        'salt': None,
        'error': None
    }
    
    try:
        if algorithm == 'md5':
            result['hash'] = hashlib.md5(text.encode('utf-8')).hexdigest()
        elif algorithm == 'sha1':
            result['hash'] = hashlib.sha1(text.encode('utf-8')).hexdigest()
        elif algorithm == 'sha256':
            result['hash'] = hashlib.sha256(text.encode('utf-8')).hexdigest()
        elif algorithm == 'sha512':
            result['hash'] = hashlib.sha512(text.encode('utf-8')).hexdigest()
        elif algorithm == 'bcrypt':
            if salt and str(salt).strip():
                # bcrypt dengan salt custom
                result['hash'] = bcrypt.hashpw(text.encode('utf-8'), salt.encode('utf-8')).decode('utf-8')
                result['salt'] = salt
            else:
                # bcrypt dengan salt otomatis
                hashed = bcrypt.hashpw(text.encode('utf-8'), bcrypt.gensalt())
                result['hash'] = hashed.decode('utf-8')
                result['salt'] = result['hash'][:29]
        elif algorithm == 'base64':
            result['hash'] = base64.b64encode(text.encode('utf-8')).decode('utf-8')
        else:
            result['error'] = f'Algoritma {algorithm} tidak didukung'
    except Exception as e:
        result['error'] = f'Error hashing ({algorithm}): {str(e)}'
    
    return result

# ==========================================
# FUNGSI GENERATE HASH DARI FILE
# ==========================================
def generate_file_hash(file_path, algorithm='sha256', chunk_size=8192):
    """
    Generate hash dari file.
    
    Args:
        file_path (str): Path file
        algorithm (str): Algoritma hash
        chunk_size (int): Ukuran chunk untuk baca file
    
    Returns:
        dict: Hasil hash file
    """
    algorithm = str(algorithm).lower().strip()
    
    result = {
        'algorithm': algorithm,
        'file': file_path,
        'hash': '',
        'size': 0,
        'error': None
    }
    
    if not file_path or not os.path.exists(file_path):
        result['error'] = 'File tidak ditemukan'
        return result
    
    if not os.path.isfile(file_path):
        result['error'] = 'Path bukan sebuah file'
        return result
    
    try:
        result['size'] = os.path.getsize(file_path)
    except Exception as e:
        result['error'] = f'Gagal membaca ukuran file: {str(e)}'
        return result
    
    try:
        hash_func = getattr(hashlib, algorithm)
    except AttributeError:
        result['error'] = f'Algoritma {algorithm} tidak didukung untuk file'
        return result
    
    hasher = hash_func()
    
    try:
        with open(file_path, 'rb') as f:
            while chunk := f.read(chunk_size):
                hasher.update(chunk)
        result['hash'] = hasher.hexdigest()
    except Exception as e:
        result['error'] = f'Gagal memproses file: {str(e)}'
    
    return result

# ==========================================
# TESTING UNIT
# ==========================================
if __name__ == '__main__':
    print("=" * 50)
    print("HASH GENERATOR - TESTING")
    print("=" * 50)
    
    test_text = "password123"
    print(f"[*] Input: {test_text}")
    
    algorithms = ['md5', 'sha1', 'sha256', 'sha512', 'bcrypt', 'base64']
    
    for algo in algorithms:
        result = generate_hash(test_text, algo)
        print(f"\n[*] {algo.upper()}:")
        if result.get('error'):
            print(f"    Error: {result['error']}")
        else:
            print(f"    Hash: {result['hash']}")
            if result.get('salt'):
                print(f"    Salt: {result['salt']}")
    
    print("\n[*] Selesai.")