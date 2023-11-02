Network Scanner (NetScan)

Author: Perthlis
Version: 1.0

## Overview

The Network Scanner (NetScan) is a simple Python tool for network discovery and port scanning. It helps identify active devices on your local network and checks for open ports on those devices. This README provides an overview of how to use the tool and its basic features.

## Features

- ARP scanning to discover active devices.
- TCP SYN scanning to identify open ports on devices.
- Supports scanning multiple target IP addresses.
- Easy-to-use command-line interface.

## Prerequisites

- Python 3.x
- Scapy library (install using `pip install scapy`)
- Linux-based operating system (recommended)

## Usage

1. Clone this repository to your local machine.
2. Open a terminal in the project directory.
3. Run the following command:

   bash
   python3 NetSeeker.sh <target_ips> <port_range>
