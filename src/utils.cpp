/*
    VUT FIT IPK
    1. Project - L4 Scanner
    Author: Jakub Lůčný (xlucnyj00)
    Date: 2025-03-16
*/

#include <iostream>
#include <vector>
#include <set>
#include <string>
#include <sstream>
#include <arpa/inet.h>
#include <netdb.h>
#include <cstring>  //memcpy
#include <ifaddrs.h>

#include <argparse/argparse.hpp>

#include "utils.h"

/*
    Helper function to parse ports from a string into a vector of integers
    Also checks for valid port numbers
*/
std::vector<int> parsePorts(const std::string& portsStr){
    std::vector<int> ports;
    if (portsStr.empty()) return ports; // nothing to parse

    std::stringstream ss(portsStr);
    std::string segment;

    // Reads until ','
    while (std::getline(ss, segment, ',')) {
        // Check if there's a '-' indicating its a range of ports
        auto dashPos = segment.find('-');
        if (dashPos != std::string::npos) {
            // range "x-y"
            int start = std::stoi(segment.substr(0, dashPos));
            int end = std::stoi(segment.substr(dashPos + 1));
            // Check for valid ports
            if (start < 1 || start > 65535 || end < 1 || end > 65535) {
                throw std::runtime_error("Invalid port range");
            }

            for (int p = start; p <= end; p++) {
                ports.push_back(p);
            }
        } else {
            // single port
            int port = std::stoi(segment);
            if (port < 1 || port > 65535) {
                throw std::runtime_error("Invalid port number");
            }
            ports.push_back(port);
        }
    }
    return ports;
}

/*
    Function to parse arguments from the command line and get their values
    Returns 0 if successful, 1 if list of available interfaces was requested
*/
int parseArguments(int argc, char* argv[], std::string& interface, std::string& target, std::vector<int>& tcpPorts, std::vector<int>& udpPorts, int& timeout){
    argparse::ArgumentParser program("ipk-l4-scan");

    program.add_description("Performs a scan of TCP or/and UDP ports on a given target device from selected network interface");
    
    // Specify all the possible arguments for the parser
    program.add_argument("--interface", "-i")
        .help("Select network interface to scan through\nIf unspecified or value is empty, list available interfaces")
        .default_value(std::string(""));

    program.add_argument("--pt", "-t")
        .help("Specify TCP port(s) to scan");

    program.add_argument("--pu", "-u")
        .help("Specify UDP port(s) to scan");

    program.add_argument("--wait", "-w")
        .help("Specify timeout to wait for a single port scan (in milliseconds)")
        .default_value(5000)
        .scan<'i', int>();

    program.add_argument("hostname")
        .help("Hostname or IP address of the scanned device")
        .default_value(std::string(""));

    // Parse the arguments and get their values
    program.parse_args(argc, argv);

    // Get interface value
    // If it's empty, means option was not used or value was not provided
    interface = program.get<std::string>("--interface");
    if (interface.empty()) {
        // No value provided, list available interfaces and end program
        listInterfaces();
        return 1;
    }

    // Check if target was provided
    target = program.get<std::string>("hostname");
    if (target.empty()) {
        throw std::runtime_error("Error: No target provided.");
    }

    // Parse port arguments
    if (program.is_used("--pt")) {
        std::string tcpStr = program.get<std::string>("--pt");
        tcpPorts = parsePorts(tcpStr);
    }

    if (program.is_used("--pu")) {
        std::string udpStr = program.get<std::string>("--pu");
        udpPorts = parsePorts(udpStr);
    }

    // Get timeout value
    timeout = program.get<int>("--wait");

    return 0;
}

/*
    Prints out a list of available network interfaces
*/
void listInterfaces() {
    struct ifaddrs* ifaddr;
    
    // Get linked list of network interfaces
    if (getifaddrs(&ifaddr) == -1) {
        std::cerr << "Failed to get list of network interfaces\n";
        return;
    }

    // Print out the interfaces
    std::cout << "Available Network Interfaces:\n";
    for (struct ifaddrs* iface = ifaddr; iface != nullptr; iface = iface->ifa_next) {
        if (iface->ifa_addr == nullptr) continue;  // Skip interfaces with no address

        auto family = iface->ifa_addr->sa_family;

        auto family_name = "AF_INET";
        if (family == AF_INET6){
            family_name = "AF_INET6";
        }
        else if (family == AF_PACKET){
            family_name = "AF_PACKET";
        }

        // Prints out all the interfaces with their type
        std::cout << " - " << std::left << std::setw(16) << iface->ifa_name << " " << family_name << "\n";    }

    freeifaddrs(ifaddr);
}

/*
    Function that takes string containing a IPv4 or IPv6 address or hostname,
    if it's hostname, DNS resolves it and returns vector of resolved addresses 
    Returns string vector of destination addresses
*/
std::vector<std::string> resolveTarget(const std::string &target) {
    std::set<std::string> addresses; // set to avoid duplicates

    sockaddr_in addr4;
    sockaddr_in6 addr6;
    char ipStr[INET6_ADDRSTRLEN];

    // Check if it's already a valid IPv4 or IPv6 address before DNS resolution
    if (inet_pton(AF_INET, target.c_str(), &addr4.sin_addr) == 1) {
        // Target is valid IPv4 address
        addresses.insert(target);
        return {addresses.begin(), addresses.end()};
    }
    else if (inet_pton(AF_INET6, target.c_str(), &addr6.sin6_addr) == 1) {
        // Target is valid IPv6 address
        addresses.insert(target);
        return {addresses.begin(), addresses.end()};
    }
    else {
        // Target is hostname
        struct addrinfo hints = {}, *res = nullptr;
        hints.ai_family = AF_UNSPEC;
        // Resolve the hostname
        if (getaddrinfo(target.c_str(), nullptr, &hints, &res) != 0) {
            throw std::runtime_error("DNS resolution failed");
        }

        // Go through all the resolved addresses
        for (auto *p = res; p != nullptr; p = p->ai_next) {
            if (p->ai_family == AF_INET) {
                auto *addr = reinterpret_cast<sockaddr_in *>(p->ai_addr);
                inet_ntop(AF_INET, &addr->sin_addr, ipStr, INET_ADDRSTRLEN);
            } else if (p->ai_family == AF_INET6) {
                auto *addr = reinterpret_cast<sockaddr_in6 *>(p->ai_addr);
                inet_ntop(AF_INET6, &addr->sin6_addr, ipStr, INET6_ADDRSTRLEN);
            } else {
                continue;
            }
            addresses.insert(ipStr);
        }

        freeaddrinfo(res);
        return {addresses.begin(), addresses.end()};
    }
}
