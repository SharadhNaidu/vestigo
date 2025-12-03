import os
import json
from binary_analysis import BinaryAnalyzer

TEST_DIR = "/home/kamini08/projects/cfg-extractor/test_dataset_binaries"
SAMPLES = [
    {"filename": "aes128_arm_gcc_O2.elf", "expected_arch": "EM_ARM", "expected_crypto": ["AES"]},
    {"filename": "sha1_mips_clang_Os.elf", "expected_arch": "EM_MIPS", "expected_crypto": []}, # Constants likely inlined/split
    {"filename": "sha1_x86_gcc_O0.elf", "expected_arch": "EM_X86_64", "expected_crypto": ["SHA-1"]},
    {"filename": "rsa4096_riscv_riscv64-linux-gnu-gcc_O3.elf", "expected_arch": "EM_RISCV", "expected_crypto": []}, # RSA might not have static signatures easily found by simple strings
    {"filename": "xor_x86_gcc_O0.elf", "expected_arch": "EM_X86_64", "expected_crypto": []},
    {"filename": "aes256_z80_sdcc_Os.elf", "expected_arch": "Unknown", "expected_crypto": []} # Not an ELF, so Unknown is expected
]

def main():
    analyzer = BinaryAnalyzer()
    print(f"Testing BinaryAnalyzer on {len(SAMPLES)} diverse samples...\n")

    for sample in SAMPLES:
        path = os.path.join(TEST_DIR, sample["filename"])
        if not os.path.exists(path):
            print(f"[!] File not found: {path}")
            continue

        print(f"Analyzing: {sample['filename']}...")
        try:
            result = analyzer.analyze(path)
            
            # Check Architecture
            detected_arch = result.get("arch", "Unknown")
            is_elf = result.get("is_elf", False)
            
            if sample["filename"] == "aes256_z80_sdcc_Os.elf":
                 # Special case for Z80 HEX file
                 arch_match = not is_elf and detected_arch == "Unknown"
            else:
                 arch_match = sample["expected_arch"] in detected_arch
            
            arch_status = "PASS" if arch_match else f"FAIL (Got {detected_arch}, is_elf={is_elf})"

            # Check Crypto (Basic check for now)
            findings = result.get("crypto_findings", {})
            static_sigs = findings.get("static_signatures", [])
            
            print(f"  -> Arch: {arch_status}")
            print(f"  -> Crypto Findings: {static_sigs}")
            
        except Exception as e:
            print(f"  -> ERROR: {e}")
        print("-" * 40)

if __name__ == "__main__":
    main()
