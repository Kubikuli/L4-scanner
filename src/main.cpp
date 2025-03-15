#include <iostream>
#include <vector>
#include <string>
#include <thread>
// #include <cstring>
#include <unistd.h>     //close
#include <arpa/inet.h>
// #include <netinet/ip.h>
// #include <netinet/tcp.h>
// #include <sys/socket.h>
// #include <pcap.h>
#include <netinet/in.h>
// #include <sys/select.h>

// #include <ifaddrs.h>
#include <netinet/in.h>
#include <netinet/ip6.h>  // for struct ip6_hdr

#include "scanner.h"
#include "tcp_scanner.h"
#include "udp_scanner.h"
#include "utils.h"

/*
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
        for (auto port : tcpPorts){
            std::cerr << "TCP IPv6\n";
            ret = TCP_scan_v6(port, destAddr6, interface);
            if (ret != 0){
                return ret;
            }
        }

        // Ports for UDP
        std::vector<std::thread> udpThreadsV6;
        for (auto port : udpPorts) {
            udpThreadsV6.emplace_back(UDP_scan_v6, port, destAddr6, interface, timeout);
        }
        // Wait for all the threads to finish
        for (auto &t : udpThreadsV6) {
            t.join();
        }
    }

    // IPv4
    else {
        // Ports for TCP
        std::vector<std::thread> tcpThreadsV4;
        for (auto port : tcpPorts) {
            tcpThreadsV4.emplace_back(TCP_scan_v4, port, destAddr4, interface, timeout);
        }
        // Wait for all the TCP threads to finish
        for (auto &t : tcpThreadsV4) {
            t.join();
        }

        // Ports for UDP
        std::vector<std::thread> udpThreadsV4;
        for (auto port : udpPorts) {
            udpThreadsV4.emplace_back(UDP_scan_v4, port, destAddr4, interface, timeout);
        }
        // Wait for all the threads to finish
        for (auto &t : udpThreadsV4) {
            t.join();
        }
    }

    return 0;
}
