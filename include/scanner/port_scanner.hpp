#ifndef PORT_SCANNER_HPP
#define PORT_SCANNER_HPP
#include <vector>
/**
 * @brief Perform a multi-threaded TCP port scan on a target host.
 *
 * This function divides the specified port range across multiple threads
 * and attempts to establish TCP connections to each port. Any port that
 * successfully accepts a connection is recorded as "open".
 *
 * Thread count is typically based on available hardware concurrency.
 *
 * @param host        Hostname or IPv4 address to scan (e.g. "127.0.0.1" or "example.com")
 * @param start_port First port in the scan range (inclusive)
 * @param end_port   Last port in the scan range (inclusive)
 *
 * @note This function blocks until all scanning threads have completed.
 */
void multi_thread_port_scan(const char* host, int start_port, int end_port);

/**
 * @brief Prints out open ports
 * 
 * This functions reads the global variable list `open_ports` and prints out the port numbers
 * 
 * @param host      Hostname or IPv4 address to scan (e.g. "127.0.0.1" or "example.com")
 * 
 * @note This function will print out nothing if a port scan is not called beforehand through multi_thread_port_scan.
 */
void print_open_ports(const char* host);

#endif