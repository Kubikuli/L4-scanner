/*
    VUT FIT IPK
    1. Project - L4 Scanner
    Author: Jakub Lůčný (xlucnyj00)
    Date: 2025-03-16
*/

#ifndef UDP_SCANNER_H
#define UDP_SCANNER_H

#include <string>

// A class for scanning UDP ports on IPv4 or IPv6 networks
// Sends packet to specified port and prints out port status
class UDPScanner {
public:
    // Constructor, takes interface network to use for scanning and timeout
    UDPScanner(const std::string& interface, int timeout): interface_(interface), timeout_(timeout) {}
    // Main public function to scan a port using UDP
    // Takes port number and destination address as arguments
    int scanV4(int port, const sockaddr_in& destAddr);
    // Same as scanV4 but for IPv6
    int scanV6(int port, const sockaddr_in6& destAddr6);

private:
    static std::mutex printMutex;
    std::string interface_;
    int timeout_;
};

#endif // UDP_SCANNER_H
