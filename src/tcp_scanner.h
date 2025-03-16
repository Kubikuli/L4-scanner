// tcp-scanner.h
#ifndef TCP_SCANNER_H
#define TCP_SCANNER_H

#include <netinet/ip.h>
#include <string>

int TCP_scan_v6(const int &tcpPort, const sockaddr_in6& destAddr6, const std::string& interface, int timeout);
int TCP_scan_v4(const int &tcpPort, const sockaddr_in& destAddr4, const std::string& interface, int timeout);


#endif // TCP_SCANNER_H
