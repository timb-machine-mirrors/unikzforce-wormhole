#!/bin/bash

./scripts/generate_grpc.sh

# build switch_agent image
docker build -f switch_agent.Dockerfile -t wormhole/switch_agent:latest .