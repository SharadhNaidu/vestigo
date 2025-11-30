#!/usr/bin/env python3

import os
import glob
import json
import csv
import math

# ============================================================
# CONFIG
# ============================================================
TARGET_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "test_dataset_json")
)

OUTPUT_JSON = "rsa_training_dataset.json"
OUTPUT_CSV  = "rsa_crypto_dataset.csv"

START_INDEX = 200
END_INDEX   = 220


# ============================================================
# ONLY REAL RSA FUNCTIONS
# ============================================================
RSA_FUNCS = [
    "rsa_generate",
    "rsa_encrypt",
    "rsa_decrypt"
]

RSA_FUNCS = [f.lower() for f in RSA_FUNCS]


# ============================================================
# DETECT KEYSIZE FROM FILENAME
# ============================================================
def detect_keysize_from_filename(filename: str):
    name = filename.lower()
    if "1024" in name:
        return "RSA-1024"
    if "2048" in name:
        return "RSA-2048"
    if "4096" in name:
        return "RSA-4096"
    return "RSA"   # fallback


# ============================================================
# SAFE STRINGIFY
# ============================================================
def stringify(func):
    try:
        return json.dumps(func, sort_keys=True).lower()
    except:
        return str(func).lower()


# ============================================================
# FEATURE EXTRACTION
# ============================================================
def extract_features(func):
    f = {}
    graph = func.get("graph_level", {}) or {}
    nodes = func.get("node_level", []) or {}
    op    = func.get("op_category_counts", {}) or {}
    cs    = func.get("crypto_signatures", {}) or {}
    data  = func.get("data_references", {}) or {}
    ent   = func.get("entropy_metrics", {}) or {}
    seq   = func.get("instruction_sequence", {}) or {}

    ncount = max(1, len(nodes))

    # ---- Graph-level features ----
    graph_keys = [
        "num_basic_blocks","num_edges","cyclomatic_complexity",
        "loop_count","loop_depth","branch_density","average_block_size",
        "num_entry_exit_paths","strongly_connected_components",
        "num_conditional_edges","num_unconditional_edges","num_loop_edges",
        "avg_edge_branch_condition_complexity"
    ]

    for k in graph_keys:
        f[k] = graph.get(k, 0)

    # ---- Node-level aggregate features ----
    f["instruction_count"] = sum(n.get("instruction_count",0) for n in nodes)
    f["immediate_entropy"] = sum(n.get("immediate_entropy",0) for n in nodes) / ncount
    f["bitwise_op_density"] = sum(n.get("bitwise_op_density",0) for n in nodes) / ncount
    f["crypto_constant_hits"] = sum(n.get("crypto_constant_hits",0) for n in nodes)
    f["branch_condition_complexity"] = sum(
        sum(n.get("branch_condition_complexity",0) for n in nodes)
        for _ in [0]
    )

    # ---- Opcode ratio averages ----
    def avg_ratio(r):
        return sum(n.get("opcode_ratios",{}).get(r,0) for n in nodes) / ncount

    ratio_keys = ["add_ratio","logical_ratio","load_store_ratio","xor_ratio",
                  "multiply_ratio","rotate_ratio"]

    for r in ratio_keys:
        f[r] = avg_ratio(r)

    # ---- Crypto signature flags ----
    f["has_aes_sbox"] = bool(cs.get("has_aes_sbox"))
    f["rsa_bigint_detected"] = bool(cs.get("rsa_bigint_detected"))
    f["has_aes_rcon"] = bool(cs.get("has_aes_rcon"))
    f["has_sha_constants"] = bool(cs.get("has_sha_constants"))

    # ---- Data references ----
    f["rodata_refs_count"] = data.get("rodata_refs_count",0)
    f["string_refs_count"] = data.get("string_refs_count",0)
    f["stack_frame_size"] = data.get("stack_frame_size",0)

    # ---- Operation category ----
    f["bitwise_ops"] = op.get("bitwise_ops",0)
    f["crypto_like_ops"] = op.get("crypto_like_ops",0)
    f["arithmetic_ops"] = op.get("arithmetic_ops",0)
    f["mem_ops_ratio"] = float(op.get("mem_ops_ratio",0))

    # ---- Entropy ----
    f["function_byte_entropy"] = ent.get("function_byte_entropy",0)
    f["opcode_entropy"]        = ent.get("opcode_entropy",0)
    f["cyclomatic_complexity_density"] = ent.get("cyclomatic_complexity_density",0)

    # ---- N-gram ----
    f["unique_ngram_count"] = seq.get("unique_ngram_count",0)

    return f



# ============================================================
# MAIN PIPELINE
# ============================================================
def process():

    files = sorted(glob.glob(os.path.join(TARGET_DIR,"*.json")))
    files = files[START_INDEX:END_INDEX]

    all_samples = []

    for jf in files:
        with open(jf,"r",encoding="utf-8") as fh:
            data = json.load(fh)

        binary = data.get("binary", os.path.basename(jf))
        keysize = detect_keysize_from_filename(binary)

        parts = binary.split("_")
        meta = {
            "filename": binary,
            "architecture":  parts[-3] if len(parts)>=4 else "unknown",
            "compiler":      parts[-2] if len(parts)>=4 else "unknown",
            "optimization":  parts[-1].split(".")[0] if len(parts)>=4 else "unknown",
        }

        for func in data.get("functions",[]):

            fname = func.get("name","")
            lname = fname.lower()
            feats = extract_features(func)

            # ----------- RSA Labeling (only 3 functions) ----------
            if lname in RSA_FUNCS:
                label = keysize
            else:
                label = "Non-Crypto"

            sample = {
                "architecture": meta["architecture"],
                "algorithm": label,
                "compiler": meta["compiler"],
                "optimization": meta["optimization"],
                "filename": meta["filename"],
                "function_name": fname,
                "function_address": func.get("address",""),
                "label": label,
                **feats
            }

            all_samples.append(sample)

    # ============================================================
    # OUTPUT FILES
    # ============================================================
    if not all_samples:
        print("[!] No samples generated.")
        return

    with open(OUTPUT_CSV,"w",newline="",encoding="utf-8") as cf:
        writer = csv.DictWriter(cf, fieldnames=all_samples[0].keys())
        writer.writeheader()
        writer.writerows(all_samples)

    with open(OUTPUT_JSON,"w",encoding="utf-8") as jf:
        json.dump(all_samples, jf, indent=2)

    print("[+] Generated RSA dataset:", OUTPUT_JSON, OUTPUT_CSV)


if __name__ == "__main__":
    process()
