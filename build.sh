#!/bin/sh

go build -ldflags="-X 'main.Version=$(git describe --tags)'"
