---
title: Writing a simple firewall in C using eBPF
readtime: true
date: 2024-07-31
tags: [linux,eBPF,low-level,networking]
---

## Pre-Requisites
System calls, C, basics of low-level programming.

## Introduction
eBPF (Extended Berkeley Packet Filter) is a technology that allows users to run custom programs within the kernel. BPF / or cBPF (classic BPF), the predecessor of eBPF provided a simple and efficient way to filter packets based on predefined rules. eBPF programs offer enhanced safety, portability, and maintainability as compared to kernel modules. There are several high-level methods available for working with eBPF programs, such as [Cilium's go library](https://github.com/cilium/ebpf), [bpftrace](https://github.com/bpftrace/bpftrace), [libbpf](https://github.com/libbpf/libbpf), etc. In this post, we'll be developing a simple network firewall that blocks all the TCP traffic on some specific ports.

Before getting started, let's get accustomed with some important terms.

### 1. Network Packet
A network packet is a unit of data transmitted over a digital network. It is typically made up of three parts: header, payload and trailer.



