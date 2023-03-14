#!/bin/bash

apt update
apt install libpcap-dev gcc -y

go build ../main.go