// udp_scanner.h
#ifndef UDP_SCANNER_H
#define UDP_SCANNER_H

#include <netinet/ip.h>
#include <string>

int UDP_scan_v4(int udpPort, const sockaddr_in& destAddr, const std::string& interface);
int UDP_scan_v6(int udpPort, const sockaddr_in6& destAddr6, const std::string& interface);

#endif // UDP_SCANNER_H
