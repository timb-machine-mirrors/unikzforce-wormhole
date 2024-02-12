#!/bin/bash


# build switch image
docker build -f switch.Dockerfile -t wormhole/switch:latest .