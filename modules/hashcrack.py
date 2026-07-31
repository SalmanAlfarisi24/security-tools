import hashlib
import bcrypt
import os
from concurrent.futures import ThreadPoolExecutor

# ==========================================
# WORDLIST DEFAULT (SAMPLE)
# ==========================================
DEFAULT_WORDLIST = [
    'password', '123456', 'admin', 'root', 'toor',
    'admin123', 'password123', '12345', 'qwerty',
    'abc123', 'letmein', 'welcome', 'monkey',
    'dragon', 'master', 'sunshine', 'princess',
    'shadow', 'superman', 'iloveyou', 'fuckyou',
    'whatever', 'computer', 'internet', 'network',
    'security', 'hacker', 'pentest', 'kali', 'linux'
]

# ==========================================
# FUNGSI HASH
# ==========================================
def md5_hash(text):
    return hashlib.md5(text.encode('utf-8')).hexdigest()

def sha1_hash(text):
    return hashlib.sha1(text.encode('utf-8')).hexdigest()

def sha256_hash(text):
    return hashlib.sha256(text.encode('utf-8')).hexdigest()

def sha512_hash(text):
    return hashlib.sha512(text.encode('utf-8')).hexdigest()

def bcrypt_hash(text):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(text.encode('utf-8'), salt).decode('utf-8')

def bcrypt_check(text, hash_value):
    try:
        return bcrypt.checkpw(text.encode('utf-8'), hash_value.encode('utf-8'))
    except:
        return False

# ==========================================
# FUNGSI CRACK
# ==========================================
def crack_hash(hash_type, hash_value, wordlist=None):
    """
    Mencoba crack hash menggunakan wordlist.
    
    Args:
        hash_type (str): md5, sha1, sha256, sha512, bcrypt
        hash_value (str): Nilai hash yang akan di-crack
        wordlist (list): Daftar kata yang akan dicoba
    
    Returns:
        dict: {
            'found': bool,
            'password': str or None,
            'type': str,
            'hash': str,
            'attempts': int,
            'wordlist_size': int
        }
    """
    if wordlist is None:
        wordlist = DEFAULT_WORDLIST
    
    hash_funcs = {
        'md5': md5_hash,
        'sha1': sha1_hash,
        'sha256': sha256_hash,
        'sha512': sha512_hash
    }
    
    attempts = 0
    
    # Untuk bcrypt
    if hash_type == 'bcrypt':
        for word in wordlist:
            attempts += 1
            if bcrypt_check(word, hash_value):
                return {
                    'found': True,
                    'password': word,
                    'type': 'bcrypt',
                    'hash': hash_value,
                    'attempts': attempts,
                    'wordlist_size': len(wordlist)
                }
        return {
            'found': False,
            'password': None,
            'type': 'bcrypt',
            'hash': hash_value,
            'attempts': attempts,
            'wordlist_size': len(wordlist)
        }
    
    # Untuk hash lainnya
    if hash_type not in hash_funcs:
        return {
            'found': False,
            'password': None,
            'type': hash_type,
            'hash': hash_value,
            'attempts': 0,
            'wordlist_size': len(wordlist),
            'error': f'Hash type "{hash_type}" tidak didukung'
        }
    
    hash_func = hash_funcs[hash_type]
    
    for word in wordlist:
        attempts += 1
        if hash_func(word) == hash_value:
            return {
                'found': True,
                'password': word,
                'type': hash_type,
                'hash': hash_value,
                'attempts': attempts,
                'wordlist_size': len(wordlist)
            }
    
    return {
        'found': False,
        'password': None,
        'type': hash_type,
        'hash': hash_value,
        'attempts': attempts,
        'wordlist_size': len(wordlist)
    }

# ==========================================
# FUNGSI UNTUK TESTING (JALAN LANGUSNG)
# ==========================================
if __name__ == '__main__':
    print("=" * 50)
    print("HASH CRACKER - TESTING")
    print("=" * 50)
    
    # Test MD5
    test_password = "admin123"
    test_hash = md5_hash(test_password)
    print(f"[*] MD5 Hash: {test_hash}")
    
    result = crack_hash('md5', test_hash)
    print(f"[*] MD5 Crack: {result['found']} -> {result['password']}")
    
    # Test SHA256
    test_hash2 = sha256_hash(test_password)
    print(f"[*] SHA256 Hash: {test_hash2}")
    
    result2 = crack_hash('sha256', test_hash2)
    print(f"[*] SHA256 Crack: {result2['found']} -> {result2['password']}")
    
    # Test dengan hash yang tidak dikenal
    unknown_hash = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"  # "password"
    result3 = crack_hash('sha256', unknown_hash)
    print(f"[*] SHA256 Crack unknown: {result3['found']} -> {result3['password']}")
    
    print("\n[*] Selesai.")