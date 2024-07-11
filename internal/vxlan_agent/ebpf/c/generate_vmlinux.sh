#!/bin/bash

# Define the output file
OUTPUT_FILE="vmlinux.h"

# Check if bpftool is installed
if ! command -v bpftool &> /dev/null
then
    echo "bpftool could not be found. Please install bpftool."
    exit 1
fi

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