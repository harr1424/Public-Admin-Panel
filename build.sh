#!/bin/bash

GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build cmd/bulletinboard/main.go

docker build -t bbfr .
