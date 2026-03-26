#*
# Configuration file
# Password Policy Parameters &
# Hashing Parameters are set from here
# It can be changed or modified from here
#
# *#

# Policy Parameters (Changeable from here)
POLICY_CONFIG = {
    "min_length": 12, # That means it must be at least 12 character long
    "min_uppercase": 1, # That means it must contain at least one uppercase character
    "min_symbol": 1, # That means it must contain at least one symbol
    "strong_entropy_threshold": 80.0,
    "moderate_entropy_threshold": 50.0,
}

# Hashing Parameters (Bcrypt and Argon2 hashes are used. These parameters can also be modified)
HASHING_CONFIG = {
    "bcrypt_rounds": 12,  # Cost Factor: 2^12 (4096) rounds
    "argon2_time_cost": 2,
    "argon2_memory_cost": 65536, # Memory-hard parameter
    "argon2_parallelism": 4,
}


DICTIONARY_FILE = "dictionary.txt" # The text file of dictionary where compromised or weak passwords are involved in. You can add new password samples if you think it is critically weak
