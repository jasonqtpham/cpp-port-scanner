#include "scanner/port_scanner.hpp"
#include "scanner/nmap_service.hpp"

#include <iostream>
#include <thread>
#include <mutex>

#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <algorithm>
#include <cstdio>
#include <vector>
using namespace std;

// Nmap service lookup
static const std::string NMAP_SERVICE_DIR = "../extras/nmap-services.txt";
NmapService nmap(NMAP_SERVICE_DIR);


static vector<string> open_ports;
static mutex vec_mtx;

in_addr resolve_hostname(const char* host) {
    struct addrinfo hints{}, *res;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host, nullptr, &hints, &res) != 0) {
        fprintf(stderr, "Error: Failed to resolve hostname for '%s'\n", host);
        exit(EXIT_FAILURE);
    }

    in_addr ip_addr = ((struct sockaddr_in*)res->ai_addr)->sin_addr;
    freeaddrinfo(res);

    return ip_addr;
}

int scan_port_range(in_addr ip_addr, int start, int end) {
    for (int port = start; port <= end; ++port) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            fprintf(stderr, "Error: Failed to create socket for port %d\n", port);
            close(sock);
            continue;
        }

        // initializing address
        sockaddr_in server_addr;
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(port);
        server_addr.sin_addr = ip_addr;

        // test port connection
        if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) == 0) {
            lock_guard<mutex> lock(vec_mtx);
            open_ports.push_back(to_string(port).append("/tcp"));
        }
        close(sock);
    }
    return 0;
}

void multi_thread_port_scan(const char* host, int start_port, int end_port) {
    in_addr ip_addr = resolve_hostname(host);

    // thread setup
    int max_threads = thread::hardware_concurrency();
    thread thread_list[max_threads];
    int interval_sz = (end_port - start_port + 1) / max_threads;
    int thread_num;

    // define port ranges for threads
    for (thread_num = 0; thread_num < max_threads; ++thread_num) {
        int range_start = start_port + (thread_num * interval_sz);
        int range_end = (thread_num == max_threads - 1) ? end_port : (range_start + interval_sz - 1);
        thread_list[thread_num] = thread(scan_port_range, ip_addr, range_start, range_end);
    }

    for (thread& t : thread_list) {
        t.join();
    }
}

void print_open_ports(const char* host) {
    std::vector<string> ports_copy;

    // Copy under lock
    {
        std::lock_guard<std::mutex> lock(vec_mtx);
        ports_copy = open_ports;
    }


    // Sort ports
    std::sort(ports_copy.begin(), ports_copy.end(),
          [](const std::string &a, const std::string &b) {
              int port_a = std::stoi(a.substr(0, a.find('/')));
              int port_b = std::stoi(b.substr(0, b.find('/')));
              return port_a < port_b;
          });

    // header banner
    printf("\n\033[1;34m===== Open Ports on %s =====\033[0m\n", host);
    printf("\033[1;37mPORT     STATE    SERVICE\033[0m\n");

    if (ports_copy.empty()) {
        printf("\033[1;37mNONE     NONE    NONE\033[0m\n");
        return;
    }

    for (string port : ports_copy) {
        string service = "unknown";
        string comment = "";
        auto service_info = nmap.find_service(port);

        if (service_info.size() != 1 && service_info[0] != "-1") {
            service = service_info[0];
            comment = service_info[1];
        }
        // prints each port line
        printf("\033[1;32m%-8s open     %-15s\033[0m",
           port.c_str(),
           service.c_str());
        
        if (!comment.empty()) {
            printf(" \033[0;37m %s\033[0m", comment.c_str());
        }
        printf("\n");
    }

    printf("\n\033[1;34mScan complete.\033[0m\n");
}

