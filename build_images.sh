#!/bin/bash


# build switch_agent image
docker build -f switch_agent.Dockerfile -t wormhole/switch_agent:latest .