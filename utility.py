import hashlib
import base64
import random
import string

def generate_key():
    characters = string.ascii_letters + string.digits + '-_'
    return ''.join(random.choice(characters) for _ in range(60))

def generate_lock(secure_key, lock_secret):
    combined = secure_key + lock_secret
    lock_hash = hashlib.sha256(combined.encode()).hexdigest()

    lock_base64 = base64.urlsafe_b64encode(lock_hash.encode()).decode()
    target_length = 75
    if len(lock_base64) < target_length:
        lock_base64 += ''.join(['x'] * (target_length - len(lock_base64)))
    else:
        lock_base64 = lock_base64[:target_length]

    lock_checksum = lock_hash[:5]
    secure_lock = lock_base64 + lock_checksum
    secure_lock = secure_lock[:80]  # Ensure exactly 80 characters

    return secure_lock

def verify_key_lock_logic(secure_key, lock, lock_secret):
    combined = secure_key + lock_secret
    expected_lock_hash = hashlib.sha256(combined.encode()).hexdigest()

    expected_lock_base64 = base64.urlsafe_b64encode(expected_lock_hash.encode()).decode()
    expected_lock_base64 = expected_lock_base64[:75]  # Main part
    expected_lock_checksum = expected_lock_hash[:5]  # Checksum part
    expected_lock = expected_lock_base64 + expected_lock_checksum
    expected_lock = expected_lock[:80]  # Ensure exactly 80 characters

    return lock == expected_lock

def extract_relevant_characters(content, length):
    extracted = ''.join(char for char in content if char.isalnum() or char in '/+=')
    return extracted[:length] if len(extracted) >= length else extracted
