#include "scanner/nmap_service.hpp"

#include <fstream>
#include <sstream>

using namespace std;

std::unordered_map<std::string, std::vector<std::string>> services_;

NmapService::NmapService(const std::string& path) {
    load_file(path);
}

void NmapService::load_file(const std::string& path) {
    ifstream file(path);
    if (!file.is_open()) {
        throw runtime_error("Failed to open nmap-services file");
    }

    string line;
    while (getline(file, line)) {
        if (line.empty() || line[0] == '#') continue;
        istringstream iss(line);

        string service_name;
        string port_proto;
        string open_frequency;
        string optional_comment;

        if (!(iss >> service_name >> port_proto >> open_frequency)) continue;
        std::getline(iss, optional_comment);

        services_[port_proto] = {service_name, optional_comment, open_frequency};
    }

}

vector<string> NmapService::find_service(const string& port_proto) {
    auto it = services_.find(port_proto);

    if (it == services_.end()) {
        return { "-1" };
    }

    return {
        it->second[0],
        it->second[1],
        it->second[2]
    };
}