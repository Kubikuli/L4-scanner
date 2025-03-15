#include <vector>
#include <string>
#include <sstream>
#include <arpa/inet.h>
#include <netdb.h>
#include <cstring> //memcpy

#include <argparse/argparse.hpp>

#include "scanner.h"
#include "utils.h"

/*
    Function to parse arguments from the command line and get their values
    Returns 0 if successful, 1 if list of available interfaces was requested
*/
int parseArguments(int argc, char* argv[], std::string& interface, std::string& target, std::vector<int>& tcpPorts, std::vector<int>& udpPorts, int& timeout){
    argparse::ArgumentParser program("ipk-l4-scan");
    
    // Specify all the arguments
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

    // Parse the arguments and get values of the arguments
    program.parse_args(argc, argv);

    // Get interface value
    // If it's empty, means option was not used or value was not provided
    interface = program.get<std::string>("--interface");
    if (interface.empty()) {
        Scanner::listInterfaces();
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

    timeout = program.get<int>("--wait");

    return 0;
}

/*
    Helper function to parse ports from a string into a vector of integers
    Also check for valid port numbers
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
    Function that takes string containing a ipv4 or ipv6 address or hostname
    and resolves it to a sockaddr_in or sockaddr_in6 structure
    Returns true if target is ipv6, false if ipv4
*/
bool resolveTarget(const std::string &target, sockaddr_in &destAddr4, sockaddr_in6 &destAddr6) {
    bool isIPv6 = false;
    memset(&destAddr4, 0, sizeof(destAddr4));
    memset(&destAddr6, 0, sizeof(destAddr6));

    if (inet_pton(AF_INET, target.c_str(), &destAddr4.sin_addr) == 1) {
        destAddr4.sin_family = AF_INET;
        std::cerr << "Target is valid IPv4: " << target << "\n";
    }
    else if (inet_pton(AF_INET6, target.c_str(), &destAddr6.sin6_addr) == 1) {
        destAddr6.sin6_family = AF_INET6;
        isIPv6 = true;
        std::cerr << "Target is valid IPv6: " << target << "\n";
    }
    else {
        std::cerr << "Target is hostname, attempting DNS resolution...\n";
        struct addrinfo hints = {}, *res = nullptr;
        hints.ai_family = AF_UNSPEC;
        if (getaddrinfo(target.c_str(), nullptr, &hints, &res) != 0) {
            throw std::runtime_error("DNS resolution failed");
        }
        if (res->ai_family == AF_INET) {
            memcpy(&destAddr4, res->ai_addr, sizeof(sockaddr_in));
            destAddr4.sin_family = AF_INET;
            std::cerr << "Hostname resolved to IPv4: "
                      << inet_ntoa(destAddr4.sin_addr) << "\n";
        } else if (res->ai_family == AF_INET6) {
            memcpy(&destAddr6, res->ai_addr, sizeof(sockaddr_in6));
            destAddr6.sin6_family = AF_INET6;
            isIPv6 = true;
            char buf[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &destAddr6.sin6_addr, buf, INET6_ADDRSTRLEN);
            std::cerr << "Hostname resolved to IPv6: " << buf << "\n";
        }
        freeaddrinfo(res);
    }

    return isIPv6;
}
