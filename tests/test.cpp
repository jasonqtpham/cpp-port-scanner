#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <thread>
#include <mutex>
#include <vector>
#include <algorithm>
#include<iostream>
#include "scanner/nmap_service.hpp"

using std::thread;
using std::vector;
using std::lock_guard;
using std::mutex;

static const std::string NMAP_SERVICE_DIR = "../extras/nmap-services.txt";
int main(int argc, char* argv[]) {
    return 0;
}