#!/usr/bin/bash
clang -fno-stack-protector -O2 -target bpf -c filteralter.c -o filteralter.o
sudo tc qdisc delete dev enp2s0.6 clsact
sudo tc qdisc add dev enp2s0.6 clsact
sudo tc filter add dev enp2s0.6 egress bpf direct-action obj filteralter.o sec .text
