import os
import sys
import subprocess
import json
import shutil
from ingest import IngestionModule
from binary_analysis import BinaryAnalyzer
from fs_scan import AdvancedLinuxAnalyzer

# Candidate URLs (D-Link, TP-Link, OpenWrt)
FIRMWARE_URLS = [
    # OpenWrt x86-64 Image (Standard, should be stable)
    "https://downloads.openwrt.org/releases/23.05.3/targets/x86/64/openwrt-23.05.3-x86-64-generic-ext4-combined.img.gz"
]
DOWNLOAD_DIR = "firmware_samples"

def download_firmware(urls, dest_dir):
    if not os.path.exists(dest_dir):
        os.makedirs(dest_dir)
    
    for url in urls:
        filename = url.split("/")[-1]
        dest_path = os.path.join(dest_dir, filename)
        
        # Clean up previous bad attempts
        if os.path.exists(dest_path):
            if os.path.getsize(dest_path) < 1024 * 1024: # < 1MB
                print(f"Removing invalid file {dest_path}")
                os.remove(dest_path)
        
        if os.path.exists(dest_path):
            print(f"Firmware already exists at {dest_path}")
            return dest_path
            
        print(f"Attempting download from {url}...")
        try:
            # Use curl -L for redirects, -f to fail on 404
            subprocess.run(["curl", "-L", "-f", "-o", dest_path, url], check=True)
            
            # Check size
            if os.path.getsize(dest_path) < 1024 * 1024: # < 1MB
                print("Downloaded file too small (likely HTML error page). Skipping.")
                os.remove(dest_path)
                continue
                
            print("Download successful.")
            return dest_path
        except Exception as e:
            print(f"Download failed: {e}")
            if os.path.exists(dest_path):
                os.remove(dest_path)
            continue
    
    print("All download attempts failed.")
    return None

def find_elf_files(root_dir):
    elfs = []
    for root, dirs, files in os.walk(root_dir):
        for f in files:
            path = os.path.join(root, f)
            # Simple check or use BinaryAnalyzer's check
            try:
                with open(path, 'rb') as fh:
                    if fh.read(4) == b'\x7fELF':
                        elfs.append(path)
            except:
                pass
    return elfs

def main():
    # 1. Download
    fw_path = download_firmware(FIRMWARE_URLS, DOWNLOAD_DIR)
    if not fw_path:
        return

    # 2. Ingest (Unpack)
    print("\n--- Step 1: Ingestion ---")
    ingestor = IngestionModule()
    ingest_report = ingestor.process(fw_path)
    print(json.dumps(ingest_report, indent=2))

    routing_decision = ingest_report["routing"]["decision"]
    extracted_path = None

    if ingest_report["extraction"]["was_extracted"]:
        extracted_path = ingest_report["extraction"]["extracted_path"]
        print(f"\nExtracted to: {extracted_path}")
    elif routing_decision == "PATH_C_BARE_METAL":
        print("\nNo extraction needed (Standalone Binary). Proceeding to analysis.")
        # For standalone binary, the 'extracted' path is effectively the file itself for analysis purposes
        # But find_elf_files expects a directory. 
        # We should handle this case specifically.
    else:
        print("Extraction failed and not a standalone binary. Aborting.")
        return

    # 3. Binary Analysis
    print("\n--- Step 2: Binary Analysis ---")
    
    if routing_decision == "PATH_C_BARE_METAL" and not extracted_path:
        # Analyze the single file directly
        # The ingestor copies it to analysis_workspace/.../filename
        # We can reconstruct that path or just use fw_path (but fw_path is in firmware_samples)
        # Better to use the one in analysis workspace if possible, but ingest report doesn't explicitly give the working copy path easily
        # Let's just use fw_path for simplicity in this test script
        print(f"Analyzing standalone binary: {fw_path}")
        analyzer = BinaryAnalyzer()
        bin_results = analyzer.analyze(fw_path)
        print(json.dumps(bin_results, indent=2))
        
    elif extracted_path:
        elf_files = find_elf_files(extracted_path)
        print(f"Found {len(elf_files)} ELF binaries.")
        
        if elf_files:
            analyzer = BinaryAnalyzer()
            # Analyze first 5 to save time in demo
            subset = elf_files[:5] 
            print(f"Analyzing first {len(subset)} binaries...")
            bin_results = analyzer.analyze(subset)
            print(json.dumps(bin_results, indent=2))
    
    # 4. Filesystem Analysis
    if routing_decision == "PATH_A_LINUX_FS" and extracted_path:
        print("\n--- Step 3: Filesystem Analysis ---")
        fs_analyzer = AdvancedLinuxAnalyzer()
        fs_report = fs_analyzer.analyze(extracted_path)
        print(json.dumps(fs_report, indent=2))
    else:
        print("\n--- Step 3: Filesystem Analysis ---")
        print("Skipping Filesystem Analysis (Not a Linux FS or no extraction).")

if __name__ == "__main__":
    main()
