import bcrypt
import math
import re
import os
import time
import string

from argon2 import PasswordHasher
from config import POLICY_CONFIG, HASHING_CONFIG, DICTIONARY_FILE

# --- Load Dictionary File Once ---
COMMON_PASSWORDS = set()
try:
    if os.path.exists(DICTIONARY_FILE):
        with open(DICTIONARY_FILE, 'r') as f:
            COMMON_PASSWORDS = {line.strip().lower() for line in f}
except Exception as e:
    print(f"Error loading dictionary: {e}")


# --- 1. Strength Analysis (Refactored to use CONFIG) ---
def check_for_compromise(password):
    # Check if the password is involved in dictionary or not
    return password.lower() in COMMON_PASSWORDS


def analyze_strength(password):
    # This logic uses the configurable values from config.py

    L = len(password)
    N = 0
    if re.search(r'[a-z]', password): N += 26  # Lowercase (a-z)
    if re.search(r'[A-Z]', password): N += 26  # Uppercase (A-Z)
    if re.search(r'[0-9]', password): N += 10  # Digits (0-9)

    # The most common punctuation/special chars such as ! and _
    if re.search(r'[^a-zA-Z0-9\s]', password): N += 32

    # Calculate Entropy (E)
    entropy_score = L * math.log2(N) if N > 0 else 0

    warnings = []

    # Dictionary/Compromise
    if check_for_compromise(password):
        warnings.append("CRITICAL: Password found in list of compromised passwords.")

    # Check 2: Length (uses POLICY_CONFIG)
    if L < POLICY_CONFIG["min_length"]:
        warnings.append(f"Warning: Insufficient length. Must be at least {POLICY_CONFIG['min_length']} characters.")

    # Check 3: Entropy (uses POLICY_CONFIG)
    if L >= POLICY_CONFIG["min_length"] and entropy_score < POLICY_CONFIG["strong_entropy_threshold"]:
        warnings.append(f"Warning: Low entropy ({entropy_score:.2f} bits). Below strong threshold.")


    else:
        # Check 3: Uppercase Count
        uppercase_count = sum(1 for char in password if char.isupper())
        if uppercase_count < POLICY_CONFIG["min_uppercase"]:
            warnings.append(f"Warning: Must contain at least {POLICY_CONFIG['min_uppercase']} uppercase letter(s).")

        # Check 4: Symbol Count
        # We use string.punctuation to define what counts as a symbol/special character
        symbol_count = sum(1 for char in password if char in string.punctuation)
        if symbol_count < POLICY_CONFIG["min_symbol"]:
            warnings.append(f"Warning: Must contain at least {POLICY_CONFIG['min_symbol']} symbol(s).")

        # Check 5: Entropy (Only check if length is met)
        if entropy_score < POLICY_CONFIG["strong_entropy_threshold"]:
            warnings.append(f"Warning: Low entropy score ({entropy_score:.2f} bits). Below strong threshold.")


    # Determine Rating
    if not warnings and entropy_score >= POLICY_CONFIG["strong_entropy_threshold"]:
        strength_rating = "Strong"
    elif entropy_score >= POLICY_CONFIG["moderate_entropy_threshold"]:
        strength_rating = "Moderate"
    else:
        strength_rating = "Weak"

    return {
        "entropy": round(entropy_score, 2),
        "length": L,
        "rating": strength_rating,
        "warnings": warnings
    }


# --- 2. Comparative Hashing  ---

def perform_comparative_hashing(password):
    password_bytes = password.encode('utf-8')
    results = {}

    # --- BCrypt Hashing ---
    start_time = time.perf_counter()
    salt_b = bcrypt.gensalt(rounds=HASHING_CONFIG["bcrypt_rounds"])
    hash_b = bcrypt.hashpw(password_bytes, salt_b).decode('utf-8')
    end_time = time.perf_counter()

    results['bcrypt'] = {
        'hash': hash_b,
        'time': round(end_time - start_time, 4),
        'cost_factor': HASHING_CONFIG["bcrypt_rounds"]
    }

    # --- Argon2 Hashing ---
    # Memory-hard KDF (Key Derivation Function)
    ph = PasswordHasher(
        time_cost=HASHING_CONFIG["argon2_time_cost"],
        memory_cost=HASHING_CONFIG["argon2_memory_cost"],
        parallelism=HASHING_CONFIG["argon2_parallelism"]
    )
    start_time = time.perf_counter()
    hash_a = ph.hash(password).split("$")[-1]  # Simplifies the output for display
    end_time = time.perf_counter()

    results['argon2'] = {
        'hash': hash_a,
        'time': round(end_time - start_time, 4),
        'params': f"t={ph.time_cost}, m={ph.memory_cost}, p={ph.parallelism}"
    }

    return results