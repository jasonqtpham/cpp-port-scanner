cmake_minimum_required(VERSION 3.20)
project(network_scanner LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Main project target
add_executable(pscan
    src/main.cpp
    src/port_scanner.cpp
    src/nmap_service.cpp
)
target_include_directories(pscan PRIVATE include)

# Test target
add_executable(test_exec
    tests/test.cpp
    src/nmap_service.cpp
)
target_include_directories(test_exec PRIVATE include)
