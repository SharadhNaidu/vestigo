#!/usr/bin/env python3
"""
Test script to verify that the updated LABEL_MAP works correctly
by checking function names from a sample JSON file.
"""

import json

# Updated LABEL_MAP from the Ghidra script
# All crypto functions now labeled as "Crypto" instead of specific algorithms
LABEL_MAP = {
    # --- AES Functions ---
    "AES128_Encrypt": "Crypto",
    "AES192_Encrypt": "Crypto", 
    "AES256_Encrypt": "Crypto",
    "AES_Encrypt": "Crypto",
    "KeyExpansion": "Crypto",
    "aes128_encrypt": "Crypto",
    "aes192_encrypt": "Crypto", 
    "aes256_encrypt": "Crypto",
    "AddRoundKey": "Crypto",
    "addroundkey": "Crypto",
    "add_round_key": "Crypto",
    "SubBytes": "Crypto", 
    "subbytes": "Crypto",
    "sub_bytes": "Crypto",
    "ShiftRows": "Crypto",
    "shiftrows": "Crypto", 
    "shift_rows": "Crypto",
    "MixColumns": "Crypto",
    "mixcolumns": "Crypto",
    "mix_columns": "Crypto",
    "xt": "Crypto",  # GF(2^8) helper
    "xtime": "Crypto",
    "keyexpansion": "Crypto",
    "key_expansion": "Crypto",
    "rotword": "Crypto",
    "subword": "Crypto",
    
    # --- RSA Functions ---
    "RSA1024_Encrypt": "Crypto",
    "RSA2048_Encrypt": "Crypto", 
    "RSA4096_Encrypt": "Crypto",
    "ModExp": "Crypto",
    "rsa_generate": "Crypto",
    "rsa_encrypt": "Crypto", 
    "rsa_decrypt": "Crypto",
    "gen_prime": "Crypto",
    "is_prime_mr": "Crypto",
    "rand_in_range": "Crypto",
    "pow_mod": "Crypto",
    "mul_mod": "Crypto", 
    "inv_mod": "Crypto",
    "egcd": "Crypto",
    "__umodti3": "Crypto",
    
    # --- SHA Functions ---
    "sha1_transform": "Crypto",
    "sha1_process": "Crypto",
    "sha256_transform": "Crypto",
    "sha256_process": "Crypto",
    "sha1_init_alt": "Crypto",
    "sha1_update_alt": "Crypto", 
    "sha1_final_alt": "Crypto",
    "sha1_compress": "Crypto",
    "sha224_alt_init": "Crypto",
    "sha224_alt_update": "Crypto",
    "sha224_alt_final": "Crypto", 
    "do_block": "Crypto",
    
    # --- ECC Functions ---
    "ec_point_double": "Crypto",
    "ec_point_add": "Crypto",
    "ec_scalar_mult": "Crypto", 
    "ecdh_compute_shared_secret": "Crypto",
    "ecdsa_sign": "Crypto",
    "ecdsa_verify": "Crypto",
    "init_demo_curve": "Crypto",
    "point_double": "Crypto",
    "point_infinity": "Crypto",
    "point_add": "Crypto", 
    "point_is_equal": "Crypto",
    "scalar_mul": "Crypto",
    "gen_keypair": "Crypto",
    "compute_shared": "Crypto",
    "ecdsa_sign_toy": "Crypto",
    "ecdsa_verify_toy": "Crypto",
    "print_point": "Crypto",
    "mod_add": "Crypto",
    "mod_sub": "Crypto",
    "mod_mul": "Crypto", 
    "mod_inv": "Crypto",
    "mod_pow": "Crypto",
    "modnorm": "Crypto",
    "__clzdi2": "Crypto",
    
    # --- PRNG Functions ---
    "prng_next": "Crypto",
    "lcg_pm_init": "Crypto",
    "lcg_pm_next": "Crypto",
    "xs64_init": "Crypto",
    "xs64_next": "Crypto", 
    "pcg32_init": "Crypto",
    "pcg32_next_u32": "Crypto",
    "sm64_init": "Crypto",
    "sm64_next": "Crypto",
    "rng_init": "Crypto",
    "rng_next": "Crypto",
    "rng_bytes": "Crypto",
    "rng_range": "Crypto", 
    "rng_double": "Crypto",
    
    # --- XOR Cipher Functions ---
    "xor_encrypt": "Crypto",
    "xor_init": "Crypto",
    "xor_encrypt_block": "Crypto",
    "xor_decrypt_block": "Crypto", 
    "xor_stream": "Crypto",
    "rol": "Crypto",
    "sub": "Crypto",
    "perm": "Crypto",
    "diff": "Crypto",
    
    # --- ChaCha20 Functions ---
    "chacha20_block": "Crypto"
}

def get_label(func_name):
    """Apply the same labeling logic as in the Ghidra script"""
    label = "Non-Crypto"
    func_lower = func_name.lower()
    for key, val in LABEL_MAP.items():
        if key.lower() in func_lower:
            label = val
            break
    return label

def test_json_file(json_file):
    """Test labeling on a JSON file"""
    print(f"\n=== Testing {json_file} ===")
    
    with open(json_file, 'r') as f:
        data = json.load(f)
    
    crypto_count = 0
    non_crypto_count = 0
    
    print(f"{'Function Name':<30} {'Original Label':<15} {'New Label':<15}")
    print("-" * 60)
    
    for func in data.get("functions", []):
        func_name = func.get("name", "")
        original_label = func.get("label", "")
        new_label = get_label(func_name)
        
        if new_label != "Non-Crypto":
            crypto_count += 1
        else:
            non_crypto_count += 1
            
        if new_label != original_label:
            print(f"{func_name:<30} {original_label:<15} {new_label:<15}")
    
    print(f"\nSummary:")
    print(f"  Crypto functions: {crypto_count}")
    print(f"  Non-crypto functions: {non_crypto_count}")
    print(f"  Total functions: {crypto_count + non_crypto_count}")

if __name__ == "__main__":
    # Test different types of crypto binaries
    test_files = [
        # "test_dataset_json/aes128_x86_clang_O3.elf_features.json",
        "test_dataset_json/rsa4096_x86_clang_O3.elf_features.json", 
        # "test_dataset_json/ecc_x86_clang_Os.elf_features.json",
        # "test_dataset_json/sha224_riscv_clang_Os.elf_features.json",
        # "test_dataset_json/prng_riscv_clang_O2.elf_features.json",
        # "test_dataset_json/xor_mips_gcc_O2.elf_features.json"
    ]
    
    for json_filepath in test_files:
        try:
            test_json_file(json_filepath)
        except Exception as e:
            print(f"Error testing {json_filepath}: {e}")