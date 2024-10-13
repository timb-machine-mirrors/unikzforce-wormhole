docker run -ti --rm -p 8070:80 \
  --cap-add CAP_SYS_ADMIN --pid=host \
  -e BPF_DIR=/sys/fs/bpf -v /sys/fs/bpf:/sys/fs/bpf \
  ghcr.io/ebpfdev/explorer:v0.0.7