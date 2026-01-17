#include "scanner/port_scanner.hpp"
#include <iostream>
#include <string.h>

void help() {
    printf(
        "Usage:\n"
        "  pscan <HOSTNAME|IP> [OPTION]\n\n"
        "Description:\n"
        "  Scan TCP ports on a target host using multiple threads.\n\n"
        "Target:\n"
        "  <HOSTNAME|IP>     Hostname (e.g. example.com) or IPv4 address\n\n"
        "Options:\n"
        "  -s                Scan system ports (1–1023)\n"
        "  -u                Scan user ports (1024–49151)\n"
        "  -p                Scan private ports (49152–65535)\n"
        "  -a                Scan all ports (1–65535)\n"
        "  -r <START> <END>  Scan a custom port range\n"
        "  -h                Display this help message\n\n"
        "Examples:\n"
        "  pscan 127.0.0.1 -s\n"
        "  pscan host.docker.internal -a\n"
        "  pscan 192.168.1.10 -r 8000 9000\n"
    );
}


int main(int argc, char* argv[]) {
    if (argc < 3) {
        help();
        return 1;
    }

    const char* host = argv[1];
    const char* flag = argv[2];

    int start_port = -1;
    int end_port   = -1;

    // ---- HELP ----
    if (strcmp(flag, "-h") == 0) {
        help();
        return 1;
    }

    // ---- SYSTEM PORTS ----
    else if (strcmp(flag, "-s") == 0 && argc == 3) {
        start_port = 1;
        end_port   = 1023;
    }

    // ---- USER PORTS ----
    else if (strcmp(flag, "-u") == 0 && argc == 3) {
        start_port = 1024;
        end_port   = 49151;
    }

    // ---- PRIVATE PORTS ----
    else if (strcmp(flag, "-p") == 0 && argc == 3) {
        start_port = 49152;
        end_port   = 65535;
    }

    // ---- ALL PORTS ----
    else if (strcmp(flag, "-a") == 0 && argc == 3) {
        start_port = 1;
        end_port   = 65535;
    }

    // ---- CUSTOM RANGE ----
    else if (strcmp(flag, "-r") == 0 && argc == 5) {
        start_port = atoi(argv[3]);
        end_port   = atoi(argv[4]);

        if (start_port < 1 || end_port > 65535 || start_port > end_port) {
            fprintf(stderr, "Invalid port range: %d-%d\n Ensure ports are within 1 - 65535", start_port, end_port);
            return 1;
        }
    }

    // ---- INVALID USAGE ----
    else {
        fprintf(stderr, "Invalid arguments.\n\n");
        help();
        return 1;
    }
    // ---- RUN SCAN ----
    multi_thread_port_scan(host, start_port, end_port);
    print_open_ports(host);
    return 0;
}