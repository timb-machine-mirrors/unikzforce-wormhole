#!/bin/bash

# Try running the ARM64 image first
echo "Trying to run the ARM64 image..."
docker run --platform linux/arm64 -ti --rm -p 8070:80 \
  --cap-add CAP_SYS_ADMIN --pid=host \
  -e BPF_DIR=/sys/fs/bpf -v /sys/fs/bpf:/sys/fs/bpf \
  ghcr.io/ebpfdev/explorer:v0.0.7

# Check if the ARM64 image is not available
if [ $? -ne 0 ]; then
  echo "ARM64 image not found. Trying to run the AMD64 image on Apple Silicon (with emulation)..."
  
  # Fallback to running the AMD64 image
  docker run --platform linux/amd64 -ti --rm -p 8070:80 \
    --cap-add CAP_SYS_ADMIN --pid=host \
    -e BPF_DIR=/sys/fs/bpf -v /sys/fs/bpf:/sys/fs/bpf \
    ghcr.io/ebpfdev/explorer:v0.0.7
fi