import os
import sys
import shutil
from ingest import IngestionModule

# Test inputs
TEST_ELF = "test_dataset_binaries/aes128_arm_gcc_O2.elf"
TEST_FW = "firmware_samples/openwrt-23.05.3-x86-64-generic-ext4-combined.img.gz"
TEST_RANDOM = "random_data.bin"

def create_random_file(path, size=1024):
    with open(path, "wb") as f:
        f.write(os.urandom(size))

def test_routing():
    print("--- Testing IngestionModule Routing Logic ---\n")
    ingestor = IngestionModule()
    
    # 1. Test Standalone ELF (PATH_C)
    print(f"Test Case 1: Standalone ELF ({TEST_ELF})")
    if os.path.exists(TEST_ELF):
        report = ingestor.process(TEST_ELF)
        decision = report["routing"]["decision"]
        print(f"Result: {decision}")
        if decision == "PATH_C_BARE_METAL":
            print("PASS: Correctly identified as Bare Metal / Standalone ELF.")
        else:
            print(f"FAIL: Expected PATH_C_BARE_METAL, got {decision}")
    else:
        print("SKIP: Test ELF not found.")
    print("-" * 40)

    # 2. Test Linux Firmware (PATH_A)
    print(f"Test Case 2: Linux Firmware ({TEST_FW})")
    if os.path.exists(TEST_FW):
        report = ingestor.process(TEST_FW)
        decision = report["routing"]["decision"]
        print(f"Result: {decision}")
        if decision == "PATH_A_LINUX_FS":
            print("PASS: Correctly identified as Linux Filesystem.")
        else:
            print(f"FAIL: Expected PATH_A_LINUX_FS, got {decision}")
    else:
        print("SKIP: Test Firmware not found.")
    print("-" * 40)

    # 3. Test Random Data (PATH_B)
    print(f"Test Case 3: Random Data ({TEST_RANDOM})")
    create_random_file(TEST_RANDOM)
    report = ingestor.process(TEST_RANDOM)
    decision = report["routing"]["decision"]
    print(f"Result: {decision}")
    if decision == "PATH_B_HARD_TARGET":
        print("PASS: Correctly identified as Hard Target (Extraction Failed).")
    else:
        print(f"FAIL: Expected PATH_B_HARD_TARGET, got {decision}")
    
    # Cleanup
    if os.path.exists(TEST_RANDOM):
        os.remove(TEST_RANDOM)
    print("-" * 40)

if __name__ == "__main__":
    test_routing()
