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
    catch (const std::runtime_error& err) {
        std::cerr << "Error: missing hostname. Try './ipk-l4-scan --help' for help\n";
        return 1;
    }

    // Resolve target hostname or IP address as string to IP address
    struct sockaddr_in destAddr4;
    struct sockaddr_in6 destAddr6;
    bool isIPv6 = resolveTarget(target, destAddr4, destAddr6);

    int ret;

    // Select IPv4 or IPv6 based on the resolved address
    // and scan all the selected ports with UDP and/or TCP
    if (isIPv6) {
        // Ports for TCP
        TCPScanner tcpScanner(interface, timeout);
        std::vector<std::thread> tcpThreadsV6;
        for (auto port : tcpPorts) {
            tcpThreadsV6.emplace_back([&tcpScanner, port, &destAddr6]() {
                tcpScanner.scanV6(port, destAddr6);
            });
        }
        // Wait for all the threads to finish
        for (auto &t : tcpThreadsV6) {
            t.join();
        }

        // Ports for UDP
        UDPScanner udpScanner(interface, timeout);
        std::vector<std::thread> udpThreadsV6;
        for (auto port : udpPorts) {
            udpThreadsV6.emplace_back([&udpScanner, port, &destAddr6]() {
                udpScanner.scanV6(port, destAddr6);
            });
        }
        // Wait for all the threads to finish
        for (auto &t : udpThreadsV6) {
            t.join();
        }
    }

    // IPv4
    else {
        TCPScanner tcpScanner(interface, timeout);
        std::vector<std::thread> tcpThreadsV4;
        for (auto port : tcpPorts) {
            tcpThreadsV4.emplace_back([&tcpScanner, port, &destAddr4]() {
                tcpScanner.scanV4(port, destAddr4);
            });
        }
        // Wait for all the TCP threads to finish
        for (auto &t : tcpThreadsV4) {
            t.join();
        }

        UDPScanner udpScanner(interface, timeout);
        std::vector<std::thread> udpThreadsV4;
        for (auto port : udpPorts) {
            udpThreadsV4.emplace_back([&udpScanner, port, &destAddr4]() {
                udpScanner.scanV4(port, destAddr4);
            });
        }
        // Wait for all the threads to finish
        for (auto &t : udpThreadsV4) {
            t.join();
        }
    }

    return 0;
}
