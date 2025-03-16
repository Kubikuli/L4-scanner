// tcp-scanner.h
#ifndef TCP_SCANNER_H
#define TCP_SCANNER_H

#include <netinet/ip.h>
#include <string>

class TCPScanner {
public:
    TCPScanner(const std::string& interface, int timeout)
        : interface_(interface), timeout_(timeout) {}
    int scanV4(int port, const sockaddr_in& destAddr4);
    int scanV6(int port, const sockaddr_in6& destAddr6);
private:
    std::string interface_;
    int timeout_;
};

#endif // TCP_SCANNER_H
