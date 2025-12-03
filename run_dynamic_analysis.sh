#!/bin/bash

# Configuration
VENV_PATH="./venv"
SYSROOT_ARM="/usr/arm-linux-gnueabihf"
SYSROOT_MIPS="/usr/mips-linux-gnu"

# Check arguments
if [ "$#" -lt 2 ]; then
    echo "Usage: $0 <binary_path> <arch> [sysroot_path]"
    echo "Example: $0 dataset_binaries/aes128_ARM_clang_O0.elf arm"
    exit 1
fi

BINARY_PATH="$1"
ARCH="$2"
SYSROOT="$3"

# Auto-detect sysroot if not provided
if [ -z "$SYSROOT" ]; then
    if [ "$ARCH" == "arm" ]; then
        SYSROOT="$SYSROOT_ARM"
        echo "Auto-detected ARM sysroot: $SYSROOT"
    elif [ "$ARCH" == "mips" ]; then
        SYSROOT="$SYSROOT_MIPS"
        echo "Auto-detected MIPS sysroot: $SYSROOT"
    else
        echo "Error: Sysroot not provided and no default found for arch '$ARCH'."
        echo "Please provide sysroot path as 3rd argument."
        exit 1
    fi
fi

# Activate Virtual Environment
if [ -f "$VENV_PATH/bin/activate" ]; then
    source "$VENV_PATH/bin/activate"
else
    echo "Error: Virtual environment not found at $VENV_PATH"
    echo "Please run: python3 -m venv venv && source venv/bin/activate && pip install frida-tools"
    exit 1
fi

# Run Dynamic Analysis
echo "Running Dynamic Analysis on $BINARY_PATH ($ARCH)..."
python3 dynamic_analysis/dynamic_main.py "$BINARY_PATH" "$ARCH" "$SYSROOT"

# Deactivate (optional, but good practice in script)
deactivate
