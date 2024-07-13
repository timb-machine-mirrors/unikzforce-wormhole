#!/bin/bash

./scripts/generate_vmlinux_header.sh
./scripts/generate_grpc.sh

# build switch_agent image
docker build -f ./cmd/test_agent/test_agent.Dockerfile -t wormhole/test_agent:latest .