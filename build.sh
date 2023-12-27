#!/bin/sh

CGO_ENABLED=0 go build -pgo=auto -ldflags="-X 'main.Version=$(git describe --tags)'"
