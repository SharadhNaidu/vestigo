# @author Vestigo Team
# @category Analysis
# @keybinding
# @menupath
# @toolbar

import ghidra
from ghidra.program.model.block import BasicBlockModel
from ghidra.program.model.pcode import PcodeOp
from ghidra.util.task import TaskMonitor
from ghidra.program.model.address import AddressSet

import json
import math
import sys

# =============================================================================
# 1. CRYPTOGRAPHIC CONSTANTS DATABASE
# =============================================================================
# "Magic Numbers" that serve as high-confidence signatures.

CRYPTO_CONSTANTS = {
    # --- AES (Rijndael) ---
    # Forward S-Box (first 16 bytes packed into 32-bit integers for detection)
    "AES_SBOX": [0x637c777b, 0xf26b6fc5, 0x3001672b, 0xfed7ab76], 
    # T-Table 0 (Optimization often used in OpenSSL)
    "AES_TE0":  [0xc66363a5, 0xf87c7c84, 0xee777799, 0xf67b7b8d], 
    # Rcon (Round Constants)
    "AES_RCON": [0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000],

    # --- SHA Family ---
    "SHA1_K":     [0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6],
    "SHA1_INIT":  [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0],
    
    "SHA256_K":   [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1],
    "SHA256_INIT":[0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a],
    "SHA224_INIT":[0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939], 

    # --- MD5 ---
    "MD5_T":      [0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee],
    "MD5_INIT":   [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476],

    # --- Stream Ciphers ---
    # ChaCha20 / Salsa20 sigma constant "expand 32-byte k"
    "CHACHA_SIG": [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574], 

    # --- Asymmetric (RSA/ECC) ---
    # Curve P-256 Prime (secp256r1)
    "P256_PRIME": [0xFFFFFFFF, 0x00000001, 0x00000000, 0x00000000], 
    # ASN.1 Sequence Header often found in RSA keys
    "ASN1_SEQ":   [0x3082], 
}

# Mapping P-Code IDs to readable strings for histograms
PCODE_MAP = {
    PcodeOp.INT_XOR: "XOR", PcodeOp.INT_AND: "AND", PcodeOp.INT_OR: "OR",
    PcodeOp.INT_LEFT: "SHL", PcodeOp.INT_RIGHT: "SHR", PcodeOp.INT_SRIGHT: "SAR",
    PcodeOp.INT_ADD: "ADD", PcodeOp.INT_SUB: "SUB", PcodeOp.INT_MULT: "MUL",
    PcodeOp.INT_DIV: "DIV", PcodeOp.INT_REM: "MOD",
    PcodeOp.INT_CARRY: "CARRY", PcodeOp.INT_SCARRY: "SCARRY",
    PcodeOp.LOAD: "LOAD", PcodeOp.STORE: "STORE",
    PcodeOp.BRANCH: "BRANCH", PcodeOp.CBRANCH: "CBRANCH",
    PcodeOp.CALL: "CALL", PcodeOp.RETURN: "RETURN",
    PcodeOp.MULTIEQUAL: "PHI" 
}

# =============================================================================
# 2. HELPER FUNCTIONS
# =============================================================================

def calculate_entropy(data_bytes):
    """Calculates Shannon Entropy of a list of byte values."""
    if not data_bytes: return 0.0
    entropy = 0
    length = len(data_bytes)
    counts = {}
    for b in data_bytes:
        counts[b] = counts.get(b, 0) + 1
    
    for count in counts.values():
        p_x = float(count) / length
        entropy -= p_x * math.log(p_x, 2)
    return entropy

def get_tarjan_scc(graph_nodes, graph_edges):
    """
    Computes Strongly Connected Components (SCC) count.
    Useful for detecting complex state machines vs simple loops.
    """
    index_counter = [0]
    stack = []
    lowlink = {}
    index = {}
    result = []
    
    def connect(node):
        index[node] = index_counter[0]
        lowlink[node] = index_counter[0]
        index_counter[0] += 1
        stack.append(node)
        
        successors = graph_edges.get(node, [])
        for successor in successors:
            if successor not in index:
                connect(successor)
                lowlink[node] = min(lowlink[node], lowlink[successor])
            elif successor in stack:
                lowlink[node] = min(lowlink[node], index[successor])
        
        if lowlink[node] == index[node]:
            connected_component = []
            while True:
                successor = stack.pop()
                connected_component.append(successor)
                if successor == node: break
            result.append(connected_component)
            
    for node in graph_nodes:
        if node not in index:
            connect(node)
            
    return len(result)

# =============================================================================
# 3. FEATURE EXTRACTION LOGIC
# =============================================================================

def extract_node_features(block, listing):
    """
    Extracts numeric features for a single Basic Block.
    """
    features = {
        "instruction_count": 0,
        "opcode_histogram": {},
        "bitwise_op_density": 0.0,
        "immediate_entropy": 0.0,
        "table_lookup_presence": False,
        "crypto_constant_hits": 0,
        "constant_flags": {}, 
        
        # R+R Resilience Features
        "carry_chain_depth": 0,
        "n_gram_repetition": 0.0,
        "simd_usage": False,
        
        "opcode_ratios": {
            "xor": 0.0, "add": 0.0, "multiply": 0.0, 
            "rotate": 0.0, "logical": 0.0, "load_store": 0.0
        }
    }
    
    instructions = listing.getCodeUnits(block, True)
    
    raw_opcodes = []
    immediates = []
    carry_chains = {} # Map output_varnode -> chain_length
    max_carry = 0
    
    counts = {k:0 for k in ["XOR","ADD","MUL","ROT","LOGIC","MEM","TOTAL"]}
    
    while instructions.hasNext():
        inst = instructions.next()
        features["instruction_count"] += 1
        
        # Use P-Code for architecture agnostic analysis
        pcode = inst.getPcode()
        for p in pcode:
            opcode_id = p.getOpcode()
            counts["TOTAL"] += 1
            
            # 1. Histogram & Categorization
            mnemonic = PCODE_MAP.get(opcode_id, "OTHER")
            features["opcode_histogram"][mnemonic] = features["opcode_histogram"].get(mnemonic, 0) + 1
            raw_opcodes.append(mnemonic)
            
            if opcode_id == PcodeOp.INT_XOR:
                counts["XOR"] += 1
                counts["LOGIC"] += 1
            elif opcode_id in [PcodeOp.INT_AND, PcodeOp.INT_OR]:
                counts["LOGIC"] += 1
            elif opcode_id == PcodeOp.INT_ADD:
                counts["ADD"] += 1
            elif opcode_id == PcodeOp.INT_MULT:
                counts["MUL"] += 1
            elif opcode_id in [PcodeOp.INT_LEFT, PcodeOp.INT_RIGHT, PcodeOp.INT_SRIGHT]:
                counts["ROT"] += 1
            elif opcode_id in [PcodeOp.LOAD, PcodeOp.STORE]:
                counts["MEM"] += 1
                # Table Lookup Check: Is offset constant or variable?
                if len(p.getInputs()) > 1:
                    offset_vn = p.getInput(1)
                    if not offset_vn.isConstant():
                        features["table_lookup_presence"] = True

            # 2. Carry Chain (RSA Detection)
            # Tracks dependency of CARRY/SCARRY outputs feeding into next instructions
            if opcode_id in [PcodeOp.INT_CARRY, PcodeOp.INT_SCARRY]:
                chain_len = 1
                for inp in p.getInputs():
                    if not inp.isConstant() and inp in carry_chains:
                        chain_len = max(chain_len, carry_chains[inp] + 1)
                out_vn = p.getOutput()
                if out_vn:
                    carry_chains[out_vn] = chain_len
                    max_carry = max(max_carry, chain_len)

            # 3. SIMD Detection (128-bit+ registers)
            out_vn = p.getOutput()
            if out_vn and out_vn.getSize() >= 16:
                features["simd_usage"] = True

            # 4. Constants Analysis
            for inp in p.getInputs():
                if inp.isConstant():
                    val = inp.getOffset()
                    # Entropy collection (byte-wise)
                    size = inp.getSize()
                    if size > 0 and size <= 8:
                        for b in range(size):
                            immediates.append((val >> (b*8)) & 0xFF)
                    
                    # Magic Constant Check
                    val32 = val & 0xFFFFFFFF
                    for algo, consts in CRYPTO_CONSTANTS.items():
                        if val32 in consts:
                            features["crypto_constant_hits"] += 1
                            features["constant_flags"][algo] = True

    # --- Ratios ---
    if counts["TOTAL"] > 0:
        features["bitwise_op_density"] = float(counts["XOR"] + counts["LOGIC"] + counts["ROT"]) / counts["TOTAL"]
        features["opcode_ratios"]["xor"] = float(counts["XOR"]) / counts["TOTAL"]
        features["opcode_ratios"]["add"] = float(counts["ADD"]) / counts["TOTAL"]
        features["opcode_ratios"]["multiply"] = float(counts["MUL"]) / counts["TOTAL"]
        features["opcode_ratios"]["rotate"] = float(counts["ROT"]) / counts["TOTAL"]
        features["opcode_ratios"]["logical"] = float(counts["LOGIC"]) / counts["TOTAL"]
        features["opcode_ratios"]["load_store"] = float(counts["MEM"]) / counts["TOTAL"]

    features["immediate_entropy"] = calculate_entropy(immediates)
    features["carry_chain_depth"] = max_carry
    
    # N-Gram Repetition (Unrolled Loop Detector)
    if len(raw_opcodes) >= 6:
        trigrams = []
        for i in range(len(raw_opcodes) - 2):
            trigrams.append(tuple(raw_opcodes[i:i+3]))
        if trigrams:
            most_common = max(set(trigrams), key=trigrams.count)
            freq = trigrams.count(most_common)
            # Score: How much of the block is composed of the repeating pattern?
            features["n_gram_repetition"] = float(freq * 3) / len(raw_opcodes)

    return features


def extract_function_data(func, current_program):
    """
    Orchestrates features for a whole function.
    """
    func_data = {
        "name": func.getName(),
        "address": func.getEntryPoint().toString(),
        "label": "Non-Crypto", 
        "graph_level": {},
        "node_level": [],
        "edge_level": []
    }
    
    block_model = BasicBlockModel(current_program)
    blocks = block_model.getCodeBlocksContaining(func.getBody(), TaskMonitor.DUMMY)
    
    node_ids = []
    adj_list = {} 
    
    num_blocks = 0
    num_edges = 0
    loop_count = 0
    loop_edges = 0
    entries = 0
    exits = 0
    
    # Iterate Blocks
    while blocks.hasNext():
        bb = blocks.next()
        num_blocks += 1
        bb_addr = bb.getMinAddress().toString()
        node_ids.append(bb_addr)
        
        # 1. Node Features
        node_feats = extract_node_features(bb, current_program.getListing())
        node_feats["address"] = bb_addr
        func_data["node_level"].append(node_feats)
        
        # 2. Edges
        destinations = bb.getDestinations(TaskMonitor.DUMMY)
        has_successor = False
        
        while destinations.hasNext():
            has_successor = True
            ref = destinations.next()
            num_edges += 1
            dst_addr = ref.getDestinationAddress().toString()
            
            if bb_addr not in adj_list: adj_list[bb_addr] = []
            adj_list[bb_addr].append(dst_addr)
            
            # Loop Detection (Back Edge)
            is_loop = ref.getDestinationAddress().compareTo(bb.getMinAddress()) < 0
            if is_loop: 
                loop_count += 1
                loop_edges += 1
            
            # Branch Complexity
            branch_complexity = 0
            flow_type = ref.getFlowType()
            if flow_type.isConditional():
                 # Heuristic: Count logic ops in source block
                 branch_complexity = node_feats["opcode_histogram"].get("AND", 0) + \
                                     node_feats["opcode_histogram"].get("OR", 0) + \
                                     node_feats["opcode_histogram"].get("XOR", 0)

            func_data["edge_level"].append({
                "src": bb_addr,
                "dst": dst_addr,
                "edge_type": "conditional" if flow_type.isConditional() else "unconditional",
                "is_loop_edge": is_loop,
                "branch_condition_complexity": branch_complexity
            })

        if bb.getSources(TaskMonitor.DUMMY).hasNext() == False:
            entries += 1
        if not has_successor:
            exits += 1

    # 3. Graph Level Features
    func_data["graph_level"] = {
        "num_basic_blocks": num_blocks,
        "num_edges": num_edges,
        "cyclomatic_complexity": num_edges - num_blocks + 2,
        "loop_count": loop_count,
        "loop_depth": 0, 
        "branch_density": float(loop_edges) / num_edges if num_edges > 0 else 0.0,
        "average_block_size": sum(n["instruction_count"] for n in func_data["node_level"]) / float(num_blocks) if num_blocks > 0 else 0,
        "num_entry_exit_paths": entries + exits,
        "strongly_connected_components": get_tarjan_scc(node_ids, adj_list)
    }
    
    return func_data

# =============================================================================
# 4. MAIN EXECUTION
# =============================================================================

def run_analysis():
    program_name = currentProgram.getName()
    print("[*] Starting Vestigo Analysis on: " + program_name)
    
    output_data = {
        "binary": program_name,
        "functions": []
    }
    
    fm = currentProgram.getFunctionManager()
    funcs = fm.getFunctions(True)
    
    for f in funcs:
        # Filter out tiny stubs
        if f.getBody().getNumAddresses() < 10:
            continue
            
        try:
            f_data = extract_function_data(f, currentProgram)
            output_data["functions"].append(f_data)
        except Exception as e:
            print("Error analyzing {}: {}".format(f.getName(), e))
            
    # Save JSON to same directory as binary
    args = getScriptArgs()
    # Default to current working directory if no arg
    out_dir = args[0] if len(args) > 0 else "."
    out_file = "{}/{}_features.json".format(out_dir, program_name)
        
    print("[*] Saving features to: " + out_file)
    
    with open(out_file, "w") as f:
        json.dump(output_data, f, indent=2)

if __name__ == "__main__":
    run_analysis()