#!/bin/bash

GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build cmd/bulletinboard/main.go

docker rm bbfr

docker build -t bbfr .

docker run --name bbfr --net auth_bridge -p 35151:35151 bbfr 