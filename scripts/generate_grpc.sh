#!/bin/bash

protoc --go_out=./cmd/test_agent/ --go-grpc_out=./cmd/test_agent/ cmd/test_agent/test_agent.proto