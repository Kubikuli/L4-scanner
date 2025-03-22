/*
    VUT FIT IPK
    1. Project - L4 Scanner
    Author: Jakub Lůčný (xlucnyj00)
    Date: 2025-03-16
*/

#include <iostream>
#include <vector>
#include <string>
#include <thread>
#include <netinet/in.h>

#include "tcp_scanner.h"
#include "udp_scanner.h"
#include "utils.h"

/**
    Parses command line arguments, sets values approriatelly,
    scans selected ports using selected TCP or UDP scan
*/
int main(int argc, char *argv[]) {
    std::string interface, target;
    std::vector<int> tcpPorts, udpPorts;
    int timeout;

    try {
        // Parse command line arguments and save values to variables given as parameters
        auto retCode = parseArguments(argc, argv, interface, target, tcpPorts, udpPorts, timeout);
        if (retCode == 1) {
            return 0;
        }
    }
    // Catch exception caused by missing hostname
    catch (const std::runtime_error& err) {
        std::cerr << "Error: missing hostname. Try './ipk-l4-scan --help' for help\n";
        return 1;
    }

    // Resolve target hostname to IP addresses
    // Or convert IP address provided from string 
    std::vector<std::string> resolvedAddresses;
    try {
        resolvedAddresses = resolveTarget(target);
    }
    catch (const std::runtime_error& err) {
        std::cerr << "Error: DNS resolution failed.\n" << err.what() << std::endl;
        return 1;
    }
    
    sockaddr_in addr4;
    sockaddr_in6 addr6;

    // Scan all resolved addresses
    for (const auto &resolved : resolvedAddresses) {
        // Select IPv4 or IPv6 based on the resolved/provided address
        // and scan all the selected ports with UDP and/or TCP
        if (inet_pton(AF_INET6, resolved.c_str(), &addr6.sin6_addr) == 1) {
            addr6.sin6_family = AF_INET6;

            // Ports for TCP
            TCPScanner tcpScanner(interface, timeout);
            // Parallel scan of all the selected TCP ports
            std::vector<std::thread> tcpThreadsV6;
            for (auto port : tcpPorts) {
                tcpThreadsV6.emplace_back([&tcpScanner, port, &addr6]() {
                    tcpScanner.scanV6(port, addr6);
                });
            }
            // Wait for all the threads to finish
            for (auto &t : tcpThreadsV6) {
                t.join();
            }

            // Ports for UDP
            UDPScanner udpScanner(interface, timeout);
            // Parallel scan of all the selected UDP ports
            std::vector<std::thread> udpThreadsV6;
            for (auto port : udpPorts) {
                udpThreadsV6.emplace_back([&udpScanner, port, &addr6]() {
                    udpScanner.scanV6(port, addr6);
                });
            }
            // Wait for all the threads to finish
            for (auto &t : udpThreadsV6) {
                t.join();
            }
        }

        // IPv4
        else if (inet_pton(AF_INET, resolved.c_str(), &addr4.sin_addr) == 1) {
            addr4.sin_family = AF_INET;

            TCPScanner tcpScanner(interface, timeout);
            // Parallel scan of all the selected TCP ports
            std::vector<std::thread> tcpThreadsV4;
            for (auto port : tcpPorts) {
                tcpThreadsV4.emplace_back([&tcpScanner, port, &addr4]() {
                    tcpScanner.scanV4(port, addr4);
                });
            }
            // Wait for all the TCP threads to finish
            for (auto &t : tcpThreadsV4) {
                t.join();
            }

            UDPScanner udpScanner(interface, timeout);
            // Parallel scan of all the selected UDP ports
            std::vector<std::thread> udpThreadsV4;
            for (auto port : udpPorts) {
                udpThreadsV4.emplace_back([&udpScanner, port, &addr4]() {
                    udpScanner.scanV4(port, addr4);
                });
            }
            // Wait for all the threads to finish
            for (auto &t : udpThreadsV4) {
                t.join();
            }
        }
        else{
            std::cerr << "Invalid address: " << resolved << std::endl;
        }
    }
    return 0;
}
