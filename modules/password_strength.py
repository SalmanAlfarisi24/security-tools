import re
import math
from collections import Counter

# ==========================================
# KONFIGURASI DAFTAR PASSWORD UMUM
# ==========================================
COMMON_PASSWORDS = set([
    'password', '123456', '123456789', 'qwerty', 'abc123',
    'monkey', 'dragon', 'master', 'sunshine', 'princess',
    'shadow', 'superman', 'iloveyou', 'fuckyou', 'whatever',
    'computer', 'internet', 'network', 'security', 'hacker',
    'admin', 'root', 'toor', 'welcome', 'letmein'
])

# ==========================================
# FUNGSI EVALUASI KEKUATAN PASSWORD
# ==========================================
def check_password_strength(password):
    """
    Evaluasi kekuatan password.
    
    Args:
        password (str): Password yang akan dievaluasi
    
    Returns:
        dict: {
            'password': str,
            'length': int,
            'score': int (0-100),
            'strength': str (Weak, Fair, Good, Strong, Very Strong),
            'feedback': list,
            'details': dict
        }
    """
    if not password:
        return {
            'password': '',
            'length': 0,
            'score': 0,
            'strength': 'Weak',
            'feedback': ['❌ Password tidak boleh kosong'],
            'details': {
                'length': 0,
                'has_uppercase': False,
                'has_lowercase': False,
                'has_digits': False,
                'has_special': False,
                'has_common': False,
                'entropy': 0
            }
        }

    score = 0
    feedback = []
    details = {
        'length': len(password),
        'has_uppercase': False,
        'has_lowercase': False,
        'has_digits': False,
        'has_special': False,
        'has_common': False,
        'entropy': 0
    }
    
    # Cek panjang password
    if len(password) >= 12:
        score += 25
        feedback.append('✅ Panjang password baik (≥ 12 karakter)')
    elif len(password) >= 8:
        score += 15
        feedback.append('✅ Panjang password cukup (≥ 8 karakter)')
    elif len(password) >= 6:
        score += 5
        feedback.append('⚠️ Panjang password minimal 6 karakter')
    else:
        feedback.append('❌ Password terlalu pendek (< 6 karakter)')
    
    # Cek huruf besar
    if re.search(r'[A-Z]', password):
        details['has_uppercase'] = True
        score += 15
        feedback.append('✅ Mengandung huruf besar')
    else:
        feedback.append('❌ Tidak mengandung huruf besar')
    
    # Cek huruf kecil
    if re.search(r'[a-z]', password):
        details['has_lowercase'] = True
        score += 10
        feedback.append('✅ Mengandung huruf kecil')
    else:
        feedback.append('❌ Tidak mengandung huruf kecil')
    
    # Cek angka
    if re.search(r'\d', password):
        details['has_digits'] = True
        score += 15
        feedback.append('✅ Mengandung angka')
    else:
        feedback.append('❌ Tidak mengandung angka')
    
    # Cek karakter khusus
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        details['has_special'] = True
        score += 20
        feedback.append('✅ Mengandung karakter khusus')
    else:
        feedback.append('❌ Tidak mengandung karakter khusus')
    
    # Cek password umum (common password)
    if password.lower() in COMMON_PASSWORDS:
        details['has_common'] = True
        score = max(0, score - 30)
        feedback.append('⚠️ Password terlalu umum/dikenal')
    
    # Cek pola berulang
    if re.search(r'(.)\1{2,}', password):
        score = max(0, score - 10)
        feedback.append('⚠️ Terdapat karakter berulang')
    
    # Cek urutan tombol keyboard
    keyboard_patterns = ['qwerty', 'asdfgh', 'zxcvbn', '123456', 'qwertyuiop', 'asdfghjkl']
    for pattern in keyboard_patterns:
        if pattern in password.lower():
            score = max(0, score - 10)
            feedback.append('⚠️ Mengandung pola keyboard yang mudah ditebak')
            break
    
    # Hitung nilai entropy (kekuatan acak karakter)
    char_set_size = 0
    if details['has_lowercase']:
        char_set_size += 26
    if details['has_uppercase']:
        char_set_size += 26
    if details['has_digits']:
        char_set_size += 10
    if details['has_special']:
        char_set_size += 32
    
    if char_set_size > 0:
        entropy = len(password) * math.log2(char_set_size)
        details['entropy'] = round(entropy, 2)
    
    # Batasi skor maksimal 100
    score = min(100, score)
    
    # Tentukan tingkatan kekuatan (strength category)
    if score >= 80:
        strength = 'Very Strong'
    elif score >= 60:
        strength = 'Strong'
    elif score >= 40:
        strength = 'Good'
    elif score >= 20:
        strength = 'Fair'
    else:
        strength = 'Weak'
    
    return {
        'password': password,
        'length': len(password),
        'score': score,
        'strength': strength,
        'feedback': feedback,
        'details': details
    }

# ==========================================
# TESTING UNIT
# ==========================================
if __name__ == '__main__':
    print("=" * 50)
    print("PASSWORD STRENGTH CHECKER - TESTING")
    print("=" * 50)
    
    test_passwords = [
        'password',
        '123456',
        'admin123',
        'P@ssw0rd!',
        'MySecureP@ssw0rd2024!',
        'a',
        'Abc123!@#',
        'qwerty123'
    ]
    
    for pw in test_passwords:
        print(f"\n[*] Testing: {pw}")
        result = check_password_strength(pw)
        print(f"    Score: {result['score']}/100")
        print(f"    Strength: {result['strength']}")
        print(f"    Entropy: {result['details']['entropy']} bits")
        print("    Feedback:")
        for fb in result['feedback'][:3]:
            print(f"      {fb}")
        if len(result['feedback']) > 3:
            print(f"      ... and {len(result['feedback']) - 3} more")
    
    print("\n[*] Selesai.")