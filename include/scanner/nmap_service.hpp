#ifndef NMAP_SERVICE_HPP
#define NMAP_SERVICE_HPP

#include <string>
#include <unordered_map>
#include <vector>

/**
 * @brief Class to parse and query Nmap service definitions from a nmap-services file.
 *
 * This class reads the Nmap services file (typically named `nmap-services`)
 * and stores mappings from port/protocol strings (e.g., "80/tcp") to service
 * information. It allows for querying the service name and optional comment
 * for a given port/protocol.
 */
class NmapService {
public:

    /**
     * @brief Constructs an NmapService object and loads the service definitions from a file.
     *
     * @param path The path to the nmap-services file.
     *
     * @throws std::runtime_error If the file cannot be opened.
     *
     * Example usage:
     * @code
     * NmapService nmap("../extras/nmap-services.txt");
     * @endcode
     */
    explicit NmapService(const std::string& path);

    /**
     * @brief Finds the service information for a given port/protocol.
     *
     * @param port_proto The port and protocol string in the form "port/protocol", e.g., "443/tcp".
     *
     * @return A vector of strings:
     * - Index 0: service name (e.g., "https")
     * - Index 1: optional comment (may be empty)
     * If the port/protocol is not found in the map, returns a vector containing a single string "-1".
     *
     * Example usage:
     * @code
     * auto result = nmap.find_service("80/tcp");
     * if (result.size() == 1 && result[0] == "-1") {
     *     // Not found
     * } else {
     *     std::string service_name = result[0];
     *     std::string comment = result[1];
     * }
     * @endcode
     */
    std::vector<std::string> find_service(const std::string& port_proto);

private:

    /**
     * @brief Loads the nmap-services file into the internal map.
     *
     * @param path Path to the nmap-services file.
     *
     * Parses each line of the file, ignoring comments and empty lines.
     * Each entry is stored in the `services_` map with the port/protocol string
     * as the key and a vector of [service_name, open_frequency, optional_comment] as the value.
     */
    void load_file(const std::string& path);

    /// Internal map storing port/protocol to service information
    std::unordered_map<std::string, std::vector<std::string>> services_;
};

#endif
