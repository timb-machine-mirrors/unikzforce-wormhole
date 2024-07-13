#!/bin/bash

# Define the output file
OUTPUT_FILE="./include/vmlinux.h"

# Check if bpftool is installed
if ! command -v pahole &> /dev/null
then
    echo "pahol could not be found. Please install pahole (dwarves package)."
    exit 1
fi

# Check if bpftool is installed
if ! command -v bpftool &> /dev/null
then
    echo "bpftool could not be found. Please install bpftool."
    exit 1
fi

# Genereting vmlinux
echo "Generating vmlinux"
pahole -J /sys/kernel/btf/vmlinux

# Generate vmlinux.h using bpftool
echo "Generating $OUTPUT_FILE..."
bpftool btf dump file /sys/kernel/btf/vmlinux format c > $OUTPUT_FILE

# Check if the generation was successful
if [ $? -eq 0 ]; then
    echo "$OUTPUT_FILE has been successfully generated."
else
    echo "Failed to generate $OUTPUT_FILE."
    exit 1
fi