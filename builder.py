import os
import subprocess
import argparse
import sys
import shutil

# Configuration Matrix
# Each architecture defines its supported compilers and specific flag mappings
ARCHITECTURES = {
    "x86_64": {
        "compilers": {
            "gcc": "gcc",
            "clang": "clang"
        },
        "base_flags": [],
        "opt_map": {} # Default: Use standard -O flags
    },
    "arm": {
        "compilers": {
            "gcc": "arm-linux-gnueabihf-gcc",
            "clang": "clang --target=arm-linux-gnueabihf"
        },
        "base_flags": ["-static"],
        "opt_map": {}
    },
    "mips": {
        "compilers": {
            "gcc": "mips-linux-gnu-gcc",
            "clang": "clang --target=mips-linux-gnu"
        },
        "base_flags": ["-static"],
        "opt_map": {}
    },
    "riscv": {
        "compilers": {
            "gcc": "riscv64-linux-gnu-gcc",
            "clang": "clang --target=riscv64-linux-gnu"
        },
        "base_flags": ["-static"],
        "opt_map": {}
    },
    "avr": {
        "compilers": {
            "gcc": "avr-gcc",
            "clang": "clang --target=avr"
        },
        "base_flags": ["-mmcu=atmega328p"],
        "opt_map": {}
    },
    "z80": {
        "compilers": {
            "sdcc": "sdcc -mz80"
        },
        "base_flags": [],
        "opt_map": {
            "-O0": "--no-peep", # Approximate
            "-O1": "--opt-code-size",
            "-O2": "--opt-code-speed",
            "-O3": "--opt-code-speed --peep-asm",
            "-Os": "--opt-code-size"
        },
        "output_ext": ".ihx" # SDCC produces .ihx by default
    }
}

OPTIMIZATIONS = ["-O0", "-O1", "-O2", "-O3", "-Os"]

IMAGE_NAME = "permutation-factory"

def run_command(cmd):
    """Runs a shell command and prints output."""
    try:
        subprocess.check_call(cmd)
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {' '.join(cmd)}\n{e}")
        return False

def build_docker_image():
    print(f"Building Docker image '{IMAGE_NAME}'...")
    return run_command(["docker", "build", "-t", IMAGE_NAME, "."])

def get_flags(arch_config, opt_level):
    """Returns the list of flags for a given optimization level."""
    # Get base flags
    flags = list(arch_config.get("base_flags", []))
    
    # Get optimization flags
    opt_map = arch_config.get("opt_map", {})
    if opt_level in opt_map:
        # Use mapped flags (split by space if multiple)
        flags.extend(opt_map[opt_level].split())
    else:
        # Use standard flag
        flags.append(opt_level)
        
    return flags

def build_matrix(source_file, output_dir):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    abs_source = os.path.abspath(source_file)
    cwd = os.getcwd()
    
    if not abs_source.startswith(cwd):
        print(f"Error: Source file {source_file} must be within the current working directory {cwd} for Docker mounting.")
        return

    rel_source = os.path.relpath(abs_source, cwd)
    source_name = os.path.splitext(os.path.basename(source_file))[0]

    print(f"Starting build matrix for {rel_source}...")

    success_count = 0
    total_count = 0

    for arch, arch_config in ARCHITECTURES.items():
        compilers = arch_config.get("compilers", {})
        
        for compiler_name, compiler_bin in compilers.items():
            for opt in OPTIMIZATIONS:
                total_count += 1
                
                output_filename = f"{source_name}_{arch}_{compiler_name}_{opt.replace('-', '')}.elf"
                container_output_path = os.path.join(output_dir, output_filename)
                
                # Handle SDCC specific output naming
                # SDCC takes -o <file.ihx> or just -o <file> (and adds extension)
                # We will let it build to a temp name and then rename if needed, 
                # but for simplicity in Docker, we'll try to force the name or rename after.
                # SDCC is tricky with -o. It expects a directory or a file with extension.
                
                flags = get_flags(arch_config, opt)
                
                cmd_parts = compiler_bin.split() + flags
                
                # Special handling for Z80/SDCC output
                if arch == "z80":
                    # SDCC outputs .ihx, .lk, .map etc.
                    # We specify output file with extension
                    temp_out = container_output_path.replace(".elf", ".ihx")
                    cmd_parts += ["-o", temp_out, rel_source]
                    
                    # We need to rename the .ihx to .elf after build (inside container or outside)
                    # Since we mount the dir, we can rename outside, but the build command is inside.
                    # We'll wrap the command in sh -c to rename inside.
                    
                    build_cmd_str = " ".join(cmd_parts)
                    # Rename .ihx to .elf
                    build_cmd = ["sh", "-c", f"{build_cmd_str} && mv {temp_out} {container_output_path}"]
                    
                else:
                    # Standard GCC/Clang
                    cmd_parts += ["-o", container_output_path, rel_source]
                    build_cmd = cmd_parts

                print(f"[{success_count+1}/{total_count}] Building {output_filename} ({arch}, {compiler_name}, {opt})...")
                
                docker_cmd = [
                    "docker", "run", "--rm",
                    "-v", f"{cwd}:/app",
                    "-w", "/app",
                    IMAGE_NAME
                ] + build_cmd

                if run_command(docker_cmd):
                    success_count += 1
                else:
                    print(f"Failed to build {output_filename}")

    print(f"\nBuild complete. {success_count}/{total_count} binaries generated in '{output_dir}'.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Permutation Factory Builder")
    parser.add_argument("--source", required=True, help="Source C file (must be in current directory or subdir)")
    parser.add_argument("--output", default="bin", help="Output directory (relative to current directory)")
    parser.add_argument("--build-image", action="store_true", help="Build the Docker image before running")
    
    args = parser.parse_args()

    if args.build_image:
        if not build_docker_image():
            sys.exit(1)

    build_matrix(args.source, args.output)
