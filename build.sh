#!/bin/sh

go build -pgo=auto -ldflags="-X 'main.Version=$(git describe --tags)'"
