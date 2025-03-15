#include <iostream>
#include <vector>
#include <string>
#include <thread>

#include <cstring>
// #include <cstdlib>
#include <unistd.h>     //close
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <pcap.h>
#include <netinet/in.h>
#include <sys/select.h>

#include <ifaddrs.h>
#include <netinet/in.h>
#include <netinet/ip6.h>  // for struct ip6_hdr

#include "scanner.h"
#include "tcp_scanner.h"
#include "udp_scanner.h"
#include "utils.h"

int main(int argc, char *argv[]) {
    std::string interface, target;
    std::vector<int> tcpPorts, udpPorts;
    int timeout;

    try {
        // Parse command line arguments
        auto retCode = parseArguments(argc, argv, interface, target, tcpPorts, udpPorts, timeout);
        if (retCode == 1) {
            return 0;
        }
    }
    catch (const std::runtime_error& err) {
        std::cerr << err.what() << "\n";
        return 1;
    }

    // Resolve target hostname or IP address as string to IP address
    struct sockaddr_in destAddr4;
    struct sockaddr_in6 destAddr6;
    bool isIPv6 = resolveTarget(target, destAddr4, destAddr6);

    int ret;

    // Select IPv4 or IPv6 based on the resolved address
    // and scan all the selected ports with UDP and TCP
    if (isIPv6) {
        // IPv6
        std::cerr << "Target is IPv6: " << target << "\n";

        // ports for TCP
        for (auto port : tcpPorts){
            // while loop tolikrat kolik je prvku v tom vektoru a pro kazdy fork 
            ret = TCP_scan_v6(port, destAddr6, interface);
            if (ret != 0){
                return ret;
            }
        }

        // Ports for UDP
        for (auto port : udpPorts){
            // Those two lines are temporary TODO
            std::cerr << "UDP scan for IPv6\n";
            ret = UDP_scan_v6(port, destAddr6, interface);
            if (ret != 0){
                return ret;
            }
        }
    }

    // IPv4
    else {
        std::cerr << "Target is IPv4: " << target << "\n";

        // Ports for TCP
        // std::cerr << "TCP scanning in parallel threads\n";
        std::vector<std::thread> tcpThreads;
        for (auto port : tcpPorts) {
            tcpThreads.emplace_back(TCP_scan_v4, port, destAddr4, interface, timeout);
        }
        // Wait for all the TCP threads to finish
        for (auto &t : tcpThreads) {
            t.join();
        }

        // Ports for UDP
        std::cerr << "UDP scanning for IPv4\n";
        for (auto port : udpPorts){
            ret = UDP_scan_v4(port, destAddr4, interface);
            if (ret != 0){
                return ret;
            }
        }
    }

    return 0;
}
