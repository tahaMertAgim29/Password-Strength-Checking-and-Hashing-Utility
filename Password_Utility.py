import bcrypt
import time
import getpass
import math
import re


COST_FACTOR = 12 # 2^(COST_FACTOR) Rounds of computation of hash to defeat attacker (Could be modified before executing)

def calculate_password_strength(password):

    L = len(password) # Holds the length of password
    N = 0 # Size of estimated char set of password

    if re.search(r'[a-z]', password): N += 26  # Lowercase (a-z)
    if re.search(r'[A-Z]', password): N += 26  # Uppercase (A-Z)
    if re.search(r'[0-9]', password): N += 10  # Digits (0-9)

    # The most common punctuation/special chars such as ! and _
    if re.search(r'[^a-zA-Z0-9\s]', password): N += 32

    # Calculate Entropy (E) (Shannon Entropy has been used)
    #*
    # Entropy is used to measure the complexity of password depending on password length and the char set used
    # The higher entropy is, the more secure the password is
    # This also expresses how much it hardens to be predictable by attackers
    # *#

    entropy_score = 0
    if N > 0:
        entropy_score = L * math.log2(N)

    # Basic Strength Rating & Warnings

    if entropy_score >= 80:
        strength_rating = "Strong Password"
    elif entropy_score >= 50:
        strength_rating = "Moderate Password"
    else:
        strength_rating = "Weak Password"

    warnings = []
    if L < 12: # This length limit could be modified before executing
        warnings.append("Warning: (Insufficient Length) Password length must include at least 12 characters")
        strength_rating = "Weak Password (Due to insufficient length)"
    if L >= 12 and entropy_score < 80:
        # Length is ok, but this time entropy is low which means it's potential to be predictable by attacker
        warnings.append(f"Warning: Low entropy score ({entropy_score:.2f} bits). Potential to be easily broken.")

    # Detailed Information for the strength analysis
    print("\n--- Strength Analysis ---")
    print(f"Password Length (L): {L}")
    print(f"Character Set Size (N): {N} (Based on detected character types)")
    print(f"Calculated Entropy: {entropy_score:.2f} bits")
    print(f"Strength Rating: {strength_rating}")
    for warning in warnings:
        print(f"  > {warning}")
    print("--------------------------------------------------------------------")

    return strength_rating


def hash_password_securely(password):


    print("--- Secure Hashing Demonstration ---")

    # Generate a salt and include the cost factor (Salting, it hardens to solve the hash for attackers)
    salt = bcrypt.gensalt(rounds=COST_FACTOR) # Rounds = 2^(COST_FACTOR) exponentially
    if len(password) < 12:
        print("Warning! Entered password has low length")


    # Hash the password (Measuring the time which takes to hash the password)
    start_time = time.perf_counter()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    end_time = time.perf_counter()

    print("Password has been successfully hashed (Demonstrating Salting & Iteration/Slowness)")
    print(f"Hashing Time:       {end_time - start_time:.4f} seconds (The required 'slowness' to deter/make them give up attackers)")
    print(f"BCrypt Cost Factor: {COST_FACTOR} (Determining iterations)")
    print(f"Secure Hash Output: {hashed_password.decode('utf-8')}")
    print("--------------------------------------------------------------------------------------")

    return hashed_password


def verify_password(password, hashed_password):
    """Verifies a password against the stored hash."""

    print("\n--- Verification Test ---")

    # bcrypt handles re-hashing with the stored salt/cost for comparison
    if bcrypt.checkpw(password.encode('utf-8'), hashed_password):
        print("Verification has been successfully done: Password is correct.")
        return True
    else:
        print("Verification FAILED: Password is incorrect.")
        return False


if __name__ == "__main__":
    print("Welcome to the Secure Password Utility (Project Demo)")

    # Step 1: Get the password securely
    try:
        test_password = getpass.getpass("Enter a password to analyze and hash: ") # Helps getting the password securely
        print(f"Entered Password (To show what is entered): {test_password}")
    except Exception as e:
        print(f"An error occurred during password input: {e}")
        exit()

    if not test_password:
        print("Password cannot be empty. Exiting.")
        exit()

    # Step 2: Analyze Strength (Demonstrates Password Policy/Design)
    calculate_password_strength(test_password)

    # Step 3: Hash Securely (Demonstrates Secure Storage)
    stored_hash = hash_password_securely(test_password)

    # Step 4: Verification (Demonstrates Authentication Flow)

    # Verify the correct password
    check_password_1 = getpass.getpass("\nEnter the SAME password to verify (SUCCESS TEST): ")
    verify_password(check_password_1, stored_hash)

    # Verify a different, incorrect password
    check_password_2 = getpass.getpass("\nEnter a DIFFERENT password to verify (FAILURE TEST): ")
    verify_password(check_password_2, stored_hash)
