# PScan – C++ Port Scanner

PScan is a lightweight TCP port scanner written in modern C++. It scans a target host for open ports and identifies common services using the official **Nmap `nmap-services` database**. The project is designed for learning low-level networking, concurrency, and clean C++ project structure.


## Features

- TCP port scanning
- Multi-threaded scanning for performance
- Service identification using `nmap-services`

## Requirements
- VS Code installed https://code.visualstudio.com/
- Docker installed https://www.docker.com/
- Dev Containers installed https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers


## Build Instructions

Clone the repository:

```bash
git clone https://github.com/jasonqtpham/cpp-port-scanner.git
cd cpp-port-scanner
```

Open the project in a DevContainer
1. Open project folder in VS Code
2. Press Ctrl+Shift+P (or Cmd+Shift+P on Mac) and type:  
“Dev Containers: Open Folder in Container”   
3. Select your project folder. VS Code will:  
    - Build the Docker container defined in .devcontainer/Dockerfile or devcontainer.json
    - Open the folder inside the container

Build with CMake:
```bash
mkdir build
cd build
cmake ..
make
```
This will generate the `pscan` executable in the build/ directory.

## Usage
```bash
./pscan <target_host> <flag>
```
Example:
```bash
./pscan 127.0.0.1 -s
```
Example output:
```perl
===== Open Ports on 127.0.0.1 =====
PORT     STATE    SERVICE
135/tcp  open     msrpc                 # epmap | Microsoft RPC services | DCE endpoint resolution
445/tcp  open     microsoft-ds          # SMB directly over IP
1042/tcp open     afrog                 # Subnet Roaming

Scan complete.
```
