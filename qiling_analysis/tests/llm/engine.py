
"""
STAGE 5 — LLM FUSION ENGINE (GEMINI 2.5 PRO ADVANCED VERSION)

INPUT:
    --input analysis.txt   ← full plaintext crypto analysis dump

OUTPUT:
    final_report.json

FEATURES:
  - Extracts metadata, static/dynamic features, syscall summary
  - LLM decides: STANDARD_CRYPTO / PROPRIETARY_CRYPTO / NON_CRYPTO
  - Extracts algorithm family, mode, loops, entropy, warnings
  - Produces frontend-ready structured JSON
"""

import json
import argparse
from pathlib import Path
import datetime
import os
from typing import Any, Dict, List

import google.generativeai as genai


def load_text(path: str) -> str:
    return Path(path).read_text(encoding="utf-8", errors="ignore")


def build_llm_prompt(plaintext: str) -> str:
    return f"""
You are a world-class firmware cryptography analyst.

You receive a large plaintext dump from a crypto-analysis tool.  
It contains:

- ELF metadata  
- YARA static signatures  
- crypto constants  
- syscall traces  
- Qiling emulator logs  
- warnings & errors  
- entropy & loop detection  
- any proprietary cipher hints  

Your tasks:

────────────────────────────────────────
### 1. Extract Important Information
Return ALL meaningful extracted metadata in the JSON:
- file format, architecture, build-id
- static crypto hits (AES_SBOX, RCON, RSA, etc.)
- dynamic behavior (entropy writes, loops, basic blocks)
- syscall behavior (getrandom, mmap, clone, file IO)
- warnings (GLIBC mismatch, invalid ELF header, etc.)
- errors (crashes)
- detected constants
- approximate execution summary

────────────────────────────────────────
### 2. Crypto Classification
Based on the entire analysis:
- Identify the primary algorithm (AES128, RSA2048, SHA256, ChaCha20, UNKNOWN)
- Identify its family (SPN, ARX, MODEXP, HASH, NTT, UNKNOWN)
- Identify variant (AES-128, AES-256, RSA-2048, etc.)
- Identify mode if block cipher (CBC/CTR/GCM/UNKNOWN)
- Identify whether crypto appears:
    * STANDARD_CRYPTO — known algorithm and normal behavior  
    * PROPRIETARY_CRYPTO — custom cipher or toy cipher  
    * NON_CRYPTO — nothing resembles cryptography  
- Provide a confidence score (0.0-1.0)

────────────────────────────────────────
### 3. Crypto Windows
If any crypto windows can be inferred:
For each:
- window_id  
- algorithm  
- crypto_family  
- proprietary (true/false)  
- confidence  
- category: STANDARD_CRYPTO / PROPRIETARY_CRYPTO / NON_CRYPTO / UNKNOWN

If no windows → return an empty array.

────────────────────────────────────────
### 4. Final Summary
Provide a short human-readable explanation summarizing:
- what the crypto is  
- why that classification  
- what evidence supports it  

────────────────────────────────────────
### JSON FORMAT — RETURN ONLY THIS STRUCTURE

{
  "metadata": {},
  "static_analysis": {},
  "dynamic_analysis": {},
  "syscalls": {},
  "warnings": [],
  "errors": [],

  "windows": [
     {
       "window_id": 0,
       "algorithm": "AES128",
       "crypto_family": "SPN",
       "proprietary": false,
       "confidence": 0.92,
       "category": "STANDARD_CRYPTO"
     }
  ],

  "primary_algorithm": "AES128",
  "crypto_family": "SPN",
  "variant": "AES-128",
  "mode": "UNKNOWN",
  "classification": "STANDARD_CRYPTO",
  "confidence": 0.94,
  "summary": "..."
}

────────────────────────────────────────

RAW ANALYSIS INPUT FOLLOWS:

{plaintext}
"""



def configure_gemini():
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        raise RuntimeError("Missing GEMINI_API_KEY environment variable.")

    genai.configure(api_key=api_key)


def call_llm(prompt: str) -> str:
    configure_gemini()

    model = genai.GenerativeModel(
        "gemini-2.5-pro",
        generation_config={
            "temperature": 0.25,
            "top_p": 0.9,
            "max_output_tokens": 8192,
            "response_mime_type": "application/json"
        }
    )

    response = model.generate_content(prompt)
    return response.text




def normalize_classification(result: Dict[str, Any]) -> str:
    classification = result.get("classification")
    if classification in ("STANDARD_CRYPTO", "PROPRIETARY_CRYPTO", "NON_CRYPTO", "UNKNOWN"):
        return classification
    return "UNKNOWN"


def run_fusion_engine(input_file: str, out_file: str):
    plaintext = load_text(input_file)

    prompt = build_llm_prompt(plaintext)
    raw_output = call_llm(prompt)

    try:
        parsed = json.loads(raw_output)
    except Exception:
        parsed = {
            "metadata": {},
            "static_analysis": {},
            "dynamic_analysis": {},
            "syscalls": {},
            "warnings": [],
            "errors": [],
            "windows": [],
            "primary_algorithm": "UNKNOWN",
            "crypto_family": "UNKNOWN",
            "variant": "UNKNOWN",
            "mode": "UNKNOWN",
            "classification": "UNKNOWN",
            "confidence": 0.0,
            "summary": "LLM returned invalid JSON.",
            "raw_output": raw_output[:2000]
        }

    parsed["classification"] = normalize_classification(parsed)

    final = {
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "source_file": input_file,
        "result": parsed
    }

    Path(out_file).write_text(json.dumps(final, indent=2), encoding="utf-8")
    print(f"[+] Fusion analysis saved → {out_file}")




def main():
    p = argparse.ArgumentParser(description="Fusion Crypto Engine — Gemini 2.5 Pro (Advanced)")
    p.add_argument("--input", required=True)
    p.add_argument("--out", default="final_report.json")
    args = p.parse_args()

    run_fusion_engine(args.input, args.out)


if __name__ == "__main__":
    main()
