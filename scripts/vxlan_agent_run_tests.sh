#!/bin/bash

go clean -testcache
go test -v ./test/e2e/vxlan_agent/