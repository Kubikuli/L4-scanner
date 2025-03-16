// tcp-scanner.h
#ifndef TCP_SCANNER_H
#define TCP_SCANNER_H

#include <string>
#include <mutex>

class TCPScanner {
public:
    TCPScanner(const std::string& interface, int timeout)
        : interface_(interface), timeout_(timeout) {}
    int scanV4(int port, const sockaddr_in& destAddr4);
    int scanV6(int port, const sockaddr_in6& destAddr6);

private:
    static std::mutex printMutex;
    std::string getLocalIPv6();
    std::string getLocalIPv4();
    static void packet_handler_v6(u_char *user, const struct pcap_pkthdr *hdr, const u_char *packet);
    static void packet_handler_v4(u_char *user, const struct pcap_pkthdr *hdr, const u_char *packet);
    int TCP_receive_packet_v6(const sockaddr_in6& destAddr6, int scannedPort);
    int TCP_receive_packet_v4(const sockaddr_in& destAddr4, int scannedPort);

    std::string interface_;
    int timeout_;
};

#endif // TCP_SCANNER_H
