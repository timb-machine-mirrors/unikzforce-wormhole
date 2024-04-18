#!/bin/bash

./scripts/generate_grpc.sh

# build switch_agent image
docker build -f test_agent.Dockerfile -t wormhole/test_agent:latest .