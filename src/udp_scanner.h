// udp_scanner.h
#ifndef UDP_SCANNER_H
#define UDP_SCANNER_H

#include <netinet/ip.h>
#include <string>

class UDPScanner {
public:
    UDPScanner(const std::string& interface, int timeout)
        : interface_(interface), timeout_(timeout) {}
    int scanV4(int port, const sockaddr_in& destAddr);
    int scanV6(int port, const sockaddr_in6& destAddr6);
private:
    std::string interface_;
    int timeout_;
};

#endif // UDP_SCANNER_H
